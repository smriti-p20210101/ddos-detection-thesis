from __future__ import annotations

import copy
import json
import math
import random
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score
from torch.optim import AdamW
from torch.optim.lr_scheduler import LambdaLR

from .config import ExperimentConfig, TaskSpec
from .data import (
    PhaseData,
    apply_scaler,
    build_phase_data,
    fit_scaler,
    get_merged_files,
    make_loader,
    split_files,
)
from .ewc import EWCState, compute_fisher, consolidate, ewc_penalty
from .model import ContinualMamba
from .replay import ReplayBuffer


@dataclass
class EvalResult:
    accuracy: float
    macro_f1: float
    latency_ms_per_sample: float


@dataclass
class TaskRuntime:
    name: str
    labels: List[str]
    data: PhaseData
    active_class_ids: List[int]
    local_map: torch.Tensor
    train_loader: Any
    val_loader: Any
    test_loader: Any


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


def select_device(device_pref: str) -> torch.device:
    if device_pref == "cuda" and torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def _class_weights(y: np.ndarray, num_classes: int, device: torch.device) -> torch.Tensor:
    counts = np.bincount(y, minlength=num_classes).astype(np.float64)
    counts[counts == 0] = 1.0
    weights = 1.0 / np.sqrt(counts)
    weights = weights / np.mean(weights)
    weights = np.clip(weights, 0.25, 4.0)
    return torch.tensor(weights, dtype=torch.float32, device=device)


def _eval_model(model: nn.Module, loader, device: torch.device) -> Tuple[np.ndarray, np.ndarray]:
    model.eval()
    ys = []
    yhat = []
    with torch.no_grad():
        for x, y in loader:
            x = x.to(device, non_blocking=True)
            logits = model(x)
            pred = torch.argmax(logits, dim=1).cpu().numpy()
            ys.append(y.numpy())
            yhat.append(pred)
    return np.concatenate(ys), np.concatenate(yhat)


def _eval_model_masked(
    model: nn.Module,
    loader,
    device: torch.device,
    active_class_ids: list[int],
) -> Tuple[np.ndarray, np.ndarray]:
    model.eval()
    ys = []
    yhat = []
    active = torch.tensor(active_class_ids, dtype=torch.long, device=device)
    with torch.no_grad():
        for x, y in loader:
            x = x.to(device, non_blocking=True)
            logits = model(x)[:, active]
            pred_local = torch.argmax(logits, dim=1)
            pred_global = active[pred_local].cpu().numpy()
            ys.append(y.numpy())
            yhat.append(pred_global)
    return np.concatenate(ys), np.concatenate(yhat)


def _measure_latency(model: nn.Module, loader, device: torch.device, warmup: int = 5, runs: int = 20) -> float:
    model.eval()
    first_batch = next(iter(loader))[0].to(device)
    with torch.no_grad():
        for _ in range(warmup):
            _ = model(first_batch)
        if device.type == "cuda":
            torch.cuda.synchronize()
        t0 = time.perf_counter()
        for _ in range(runs):
            _ = model(first_batch)
        if device.type == "cuda":
            torch.cuda.synchronize()
        elapsed = time.perf_counter() - t0
    return (elapsed / runs) * 1000.0 / max(first_batch.shape[0], 1)


def evaluate(
    model: nn.Module,
    loader,
    device: torch.device,
    active_class_ids: list[int] | None = None,
) -> EvalResult:
    if active_class_ids is None:
        y_true, y_pred = _eval_model(model, loader, device)
    else:
        y_true, y_pred = _eval_model_masked(model, loader, device, active_class_ids)
    acc = float(accuracy_score(y_true, y_pred))
    mf1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    latency = float(_measure_latency(model, loader, device))
    return EvalResult(accuracy=acc, macro_f1=mf1, latency_ms_per_sample=latency)


def _local_index_tensor(num_classes: int, active_class_ids: list[int], device: torch.device) -> torch.Tensor:
    out = torch.full((num_classes,), -1, dtype=torch.long, device=device)
    for j, c in enumerate(active_class_ids):
        out[c] = j
    return out


def _subset_ce_loss(
    logits: torch.Tensor,
    y_global: torch.Tensor,
    active_class_ids: list[int],
    local_map: torch.Tensor,
    label_smoothing: float,
    class_weights_global: torch.Tensor | None,
) -> torch.Tensor:
    active = torch.tensor(active_class_ids, dtype=torch.long, device=logits.device)
    logits_local = logits[:, active]
    y_local = local_map[y_global]
    if class_weights_global is not None:
        w_local = class_weights_global[active]
    else:
        w_local = None
    return F.cross_entropy(logits_local, y_local, weight=w_local, label_smoothing=label_smoothing)


def _ewc_loss(model: nn.Module, ewc_states: list[EWCState], ewc_lambda: float) -> torch.Tensor:
    if not ewc_states or ewc_lambda <= 0.0:
        return torch.tensor(0.0, device=next(model.parameters()).device)
    total = torch.tensor(0.0, device=next(model.parameters()).device)
    for state in ewc_states:
        total = total + ewc_penalty(model, state)
    return 0.5 * ewc_lambda * total


def _scheduler_for(optimizer, scheduler_name: str, epochs: int, warmup_epochs: int):
    scheduler_name = scheduler_name.lower()
    if scheduler_name in {"", "none"}:
        return None

    def lr_lambda(epoch: int) -> float:
        if warmup_epochs > 0 and epoch < warmup_epochs:
            return float(epoch + 1) / float(warmup_epochs)
        if scheduler_name == "cosine":
            denom = max(epochs - warmup_epochs, 1)
            progress = min(max((epoch - warmup_epochs) / denom, 0.0), 1.0)
            return 0.5 * (1.0 + math.cos(math.pi * progress))
        return 1.0

    return LambdaLR(optimizer, lr_lambda=lr_lambda)


def train_epoch(
    model: nn.Module,
    loader,
    optimizer,
    criterion,
    device: torch.device,
    grad_clip_norm: float,
    ewc_states: list[EWCState] | None = None,
    ewc_lambda: float = 0.0,
    active_class_ids: list[int] | None = None,
    local_map: torch.Tensor | None = None,
    class_weights_global: torch.Tensor | None = None,
    label_smoothing: float = 0.0,
    replay_buffer: ReplayBuffer | None = None,
    replay_method: str = "none",
    replay_batch_size: int = 0,
    replay_alpha: float = 1.0,
    der_alpha: float = 0.5,
    teacher_model: nn.Module | None = None,
    distill_class_ids: list[int] | None = None,
    lwf_alpha: float = 1.0,
    lwf_temperature: float = 2.0,
) -> float:
    model.train()
    losses = []
    replay_method = replay_method.lower()
    for x, y in loader:
        x = x.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        optimizer.zero_grad(set_to_none=True)
        logits = model(x)
        if active_class_ids is None or local_map is None:
            loss = criterion(logits, y)
        else:
            loss = _subset_ce_loss(
                logits=logits,
                y_global=y,
                active_class_ids=active_class_ids,
                local_map=local_map,
                label_smoothing=label_smoothing,
                class_weights_global=class_weights_global,
            )

        if replay_buffer is not None and replay_method in {"er", "derpp", "er_ace"}:
            replay = replay_buffer.sample(replay_batch_size, device)
            if replay is not None:
                replay_logits = model(replay.x)
                replay_ce = F.cross_entropy(
                    replay_logits,
                    replay.y,
                    label_smoothing=label_smoothing,
                )
                loss = loss + replay_alpha * replay_ce
                if replay_method == "derpp" and replay.logits is not None:
                    replay_kd = F.mse_loss(replay_logits, replay.logits)
                    loss = loss + der_alpha * replay_kd

        if teacher_model is not None and replay_method in {"lwf", "lwf_ewc"}:
            with torch.no_grad():
                teacher_logits = teacher_model(x)
            student_logits = logits
            if distill_class_ids:
                distill_ids = torch.tensor(distill_class_ids, dtype=torch.long, device=device)
                student_logits = student_logits[:, distill_ids]
                teacher_logits = teacher_logits[:, distill_ids]
            temperature = max(float(lwf_temperature), 1e-6)
            lwf_loss = F.kl_div(
                F.log_softmax(student_logits / temperature, dim=1),
                F.softmax(teacher_logits / temperature, dim=1),
                reduction="batchmean",
            ) * (temperature**2)
            loss = loss + lwf_alpha * lwf_loss

        loss = loss + _ewc_loss(model, ewc_states or [], ewc_lambda)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip_norm)
        optimizer.step()
        losses.append(loss.item())
    return float(np.mean(losses))


def _epochs_for_task(training: Dict[str, Any], task_name: str, task_idx: int) -> int:
    if "epochs_per_task" in training:
        return int(training["epochs_per_task"])
    task_key = f"epochs_{task_name}"
    if task_key in training:
        return int(training[task_key])
    legacy_key = "epochs_phase1" if task_idx == 0 else "epochs_phase2"
    if legacy_key in training:
        return int(training[legacy_key])
    return 6


def _fisher_summary(fisher: Dict[str, torch.Tensor], top_k: int = 8) -> Dict[str, Any]:
    rows = []
    total = 0.0
    count = 0
    max_value = 0.0
    for name, value in fisher.items():
        detached = value.detach()
        mean_value = float(detached.mean().item())
        sum_value = float(detached.sum().item())
        max_param = float(detached.max().item())
        rows.append(
            {
                "parameter": name,
                "mean": mean_value,
                "sum": sum_value,
                "max": max_param,
            }
        )
        total += sum_value
        count += int(detached.numel())
        max_value = max(max_value, max_param)
    rows.sort(key=lambda item: item["sum"], reverse=True)
    return {
        "total": total,
        "mean": total / max(count, 1),
        "max": max_value,
        "top_parameters": rows[:top_k],
    }


def _remap_to_global(
    y_local: np.ndarray,
    task_labels: list[str],
    global_map: Dict[str, int],
) -> np.ndarray:
    sorted_labels = sorted(task_labels)
    mapped = np.zeros_like(y_local)
    for i, lid in enumerate(y_local):
        mapped[i] = global_map[sorted_labels[lid]]
    return mapped


def _build_task_runtimes(
    config: ExperimentConfig,
    file_splits: Dict[str, list[Path]],
    device: torch.device,
) -> tuple[list[TaskRuntime], list[str], list[str]]:
    task_specs = config.resolved_tasks()
    if len(task_specs) < 2:
        raise ValueError("Continual learning requires at least two tasks.")

    task_data: list[tuple[TaskSpec, PhaseData]] = []
    feature_cols: list[str] | None = None
    for idx, task in enumerate(task_specs):
        data, cols = build_phase_data(
            file_splits=file_splits,
            phase_labels=task.labels,
            max_samples_per_split=config.max_samples_per_split,
            phase_name=task.name,
            seed=config.seed + idx * 100,
        )
        if feature_cols is None:
            feature_cols = cols
        elif cols != feature_cols:
            raise ValueError(f"Feature columns differ for task `{task.name}`.")
        task_data.append((task, data))

    all_labels = sorted({label for task in task_specs for label in task.labels})
    global_map = {lbl: i for i, lbl in enumerate(all_labels)}
    n_classes = len(all_labels)
    batch_size = int(config.training["batch_size"])
    num_workers = int(config.training["num_workers"])

    assert feature_cols is not None
    scaler = fit_scaler(task_data[0][1].x_train)
    runtimes = []
    for task, data in task_data:
        data = apply_scaler(data, scaler)
        data.y_train = _remap_to_global(data.y_train, task.labels, global_map)
        data.y_val = _remap_to_global(data.y_val, task.labels, global_map)
        data.y_test = _remap_to_global(data.y_test, task.labels, global_map)
        active_ids = sorted([global_map[x] for x in task.labels])
        runtimes.append(
            TaskRuntime(
                name=task.name,
                labels=task.labels,
                data=data,
                active_class_ids=active_ids,
                local_map=_local_index_tensor(n_classes, active_ids, device),
                train_loader=make_loader(data.x_train, data.y_train, batch_size, num_workers, shuffle=True),
                val_loader=make_loader(data.x_val, data.y_val, batch_size, num_workers, shuffle=False),
                test_loader=make_loader(data.x_test, data.y_test, batch_size, num_workers, shuffle=False),
            )
        )
    return runtimes, feature_cols, all_labels


def _evaluate_seen_tasks(
    model: nn.Module,
    tasks: list[TaskRuntime],
    seen_count: int,
    device: torch.device,
) -> list[EvalResult]:
    return [
        evaluate(model, tasks[j].test_loader, device, active_class_ids=tasks[j].active_class_ids)
        for j in range(seen_count)
    ]


def _summarize_stream(
    task_names: list[str],
    acc_matrix: list[list[float]],
    f1_matrix: list[list[float]],
    latency_matrix: list[list[float]],
) -> Dict[str, Any]:
    n_tasks = len(task_names)
    final_accs = acc_matrix[-1]
    final_f1s = f1_matrix[-1]
    avg_accuracy = float(np.mean(final_accs))
    avg_macro_f1 = float(np.mean(final_f1s))
    initial_accs = [acc_matrix[i][i] for i in range(n_tasks)]
    bwt_terms = [final_accs[i] - initial_accs[i] for i in range(n_tasks - 1)]
    bwt = float(np.mean(bwt_terms)) if bwt_terms else 0.0
    forgetting_terms = []
    for task_idx in range(n_tasks - 1):
        best_seen = max(row[task_idx] for row in acc_matrix[task_idx:])
        forgetting_terms.append(best_seen - final_accs[task_idx])
    forgetting = float(np.mean(forgetting_terms)) if forgetting_terms else 0.0

    metrics: Dict[str, Any] = {
        "num_tasks": n_tasks,
        "task_names": task_names,
        "accuracy_matrix": acc_matrix,
        "macro_f1_matrix": f1_matrix,
        "latency_matrix": latency_matrix,
        "average_accuracy_ak": avg_accuracy,
        "average_macro_f1_final": avg_macro_f1,
        "bwt": bwt,
        "average_forgetting": forgetting,
    }
    for idx, name in enumerate(task_names):
        metrics[f"{name}_test_acc_after_final"] = final_accs[idx]
        metrics[f"{name}_test_macro_f1_after_final"] = final_f1s[idx]
        metrics[f"{name}_latency_ms_per_sample_after_final"] = latency_matrix[-1][idx]

    if n_tasks == 2:
        metrics.update(
            {
                "phase1_test_acc_before_phase2": acc_matrix[0][0],
                "phase1_test_acc_after_phase2": acc_matrix[1][0],
                "phase2_test_acc_after_phase2": acc_matrix[1][1],
                "phase1_test_macro_f1_after_phase2": f1_matrix[1][0],
                "phase2_test_macro_f1_after_phase2": f1_matrix[1][1],
                "phase1_latency_ms_per_sample": latency_matrix[1][0],
                "phase2_latency_ms_per_sample": latency_matrix[1][1],
            }
        )
    return metrics


def run_experiment(config: ExperimentConfig) -> Dict[str, Any]:
    set_seed(config.seed)
    device = select_device(config.device)
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = get_merged_files(config.resolved_dataset_sources())
    file_splits = split_files(
        files=files,
        train_ratio=config.file_split["train_ratio"],
        val_ratio=config.file_split["val_ratio"],
    )
    tasks, feature_cols, all_labels = _build_task_runtimes(config, file_splits, device)
    n_classes = len(all_labels)

    model = ContinualMamba(
        input_dim=len(feature_cols),
        num_classes=n_classes,
        d_model=int(config.model["d_model"]),
        seq_len=int(config.model["seq_len"]),
        ssm_layers=int(config.model["ssm_layers"]),
        kan_hidden=int(config.model["kan_hidden"]),
        kan_grid=int(config.model["kan_grid"]),
        dropout=float(config.model["dropout"]),
        variant=str(config.model.get("variant", "mamba_kan")),
    ).to(device)

    continual_cfg = config.continual or {}
    replay_method = str(continual_cfg.get("method", "ewc" if float(config.ewc.get("lambda", 0.0)) > 0 else "finetune"))
    replay_method = replay_method.lower()
    buffer_size = int(continual_cfg.get("buffer_size", 0))
    replay_batch_size = int(continual_cfg.get("replay_batch_size", int(config.training["batch_size"]) // 2))
    replay_alpha = float(continual_cfg.get("replay_alpha", 1.0))
    der_alpha = float(continual_cfg.get("der_alpha", 0.5))
    lwf_alpha = float(continual_cfg.get("lwf_alpha", 1.0))
    lwf_temperature = float(continual_cfg.get("lwf_temperature", 2.0))
    store_logits = replay_method == "derpp"
    replay_buffer = ReplayBuffer(buffer_size, seed=config.seed) if replay_method in {"er", "derpp", "er_ace"} else None

    lr = float(config.training["lr"])
    wd = float(config.training["weight_decay"])
    grad_clip = float(config.training["grad_clip_norm"])
    label_smoothing = float(config.training["label_smoothing"])
    ewc_lambda = float(config.ewc.get("lambda", 0.0))
    fisher_batches = int(config.ewc.get("fisher_batches", 0))
    scheduler_name = str(config.training.get("scheduler", "none"))
    warmup_epochs = int(config.training.get("warmup_epochs", 0))

    ewc_states: list[EWCState] = []
    acc_matrix: list[list[float]] = []
    f1_matrix: list[list[float]] = []
    latency_matrix: list[list[float]] = []
    history: list[dict[str, Any]] = []
    fisher_summaries: list[dict[str, Any]] = []
    teacher_model: nn.Module | None = None
    distill_class_ids: list[int] = []

    for task_idx, task in enumerate(tasks):
        epochs = _epochs_for_task(config.training, task.name, task_idx)
        class_w = _class_weights(task.data.y_train, n_classes, device=device)
        criterion = nn.CrossEntropyLoss(weight=class_w, label_smoothing=label_smoothing)
        optimizer = AdamW(model.parameters(), lr=lr, weight_decay=wd)
        scheduler = _scheduler_for(optimizer, scheduler_name, epochs, warmup_epochs)

        for epoch in range(epochs):
            train_loss = train_epoch(
                model=model,
                loader=task.train_loader,
                optimizer=optimizer,
                criterion=criterion,
                device=device,
                grad_clip_norm=grad_clip,
                ewc_states=ewc_states,
                ewc_lambda=ewc_lambda,
                active_class_ids=task.active_class_ids,
                local_map=task.local_map,
                class_weights_global=class_w,
                label_smoothing=label_smoothing,
                replay_buffer=replay_buffer,
                replay_method=replay_method,
                replay_batch_size=replay_batch_size,
                replay_alpha=replay_alpha,
                der_alpha=der_alpha,
                teacher_model=teacher_model,
                distill_class_ids=distill_class_ids,
                lwf_alpha=lwf_alpha,
                lwf_temperature=lwf_temperature,
            )
            val = evaluate(model, task.val_loader, device, active_class_ids=task.active_class_ids)
            if scheduler is not None:
                scheduler.step()
            history.append(
                {
                    "task": task.name,
                    "task_index": task_idx,
                    "epoch": epoch + 1,
                    "train_loss": train_loss,
                    "val_accuracy": val.accuracy,
                    "val_macro_f1": val.macro_f1,
                    "lr": optimizer.param_groups[0]["lr"],
                }
            )

        seen_results = _evaluate_seen_tasks(model, tasks, task_idx + 1, device)
        acc_matrix.append([r.accuracy for r in seen_results])
        f1_matrix.append([r.macro_f1 for r in seen_results])
        latency_matrix.append([r.latency_ms_per_sample for r in seen_results])

        if replay_buffer is not None:
            replay_buffer.add_examples(
                x=task.data.x_train,
                y=task.data.y_train,
                model=model,
                device=device,
                batch_size=int(config.training["batch_size"]),
                store_logits=store_logits,
            )

        if replay_method in {"lwf", "lwf_ewc"}:
            teacher_model = copy.deepcopy(model).to(device)
            teacher_model.eval()
            for param in teacher_model.parameters():
                param.requires_grad_(False)
            distill_class_ids = sorted({class_id for old_task in tasks[: task_idx + 1] for class_id in old_task.active_class_ids})

        if ewc_lambda > 0.0 and fisher_batches > 0:
            fisher = compute_fisher(
                model=model,
                data_loader=task.train_loader,
                criterion=nn.CrossEntropyLoss(),
                device=device,
                max_batches=fisher_batches,
                active_class_ids=task.active_class_ids,
                local_map=task.local_map,
                label_smoothing=label_smoothing,
                class_weights_global=class_w if str(config.ewc.get("fisher_weighting", "none")).lower() in {"class_frequency", "class_frequency_aware", "cfa"} else None,
            )
            fisher_summaries.append(
                {
                    "task": task.name,
                    "task_index": task_idx,
                    **_fisher_summary(fisher),
                }
            )
            ewc_states.append(consolidate(model, fisher))

    metrics = _summarize_stream(
        task_names=[task.name for task in tasks],
        acc_matrix=acc_matrix,
        f1_matrix=f1_matrix,
        latency_matrix=latency_matrix,
    )
    metrics.update(
        {
            "num_features": len(feature_cols),
            "num_classes_union": n_classes,
            "device": str(device),
            "continual_method": replay_method,
            "replay_buffer_size": len(replay_buffer) if replay_buffer is not None else 0,
            "ewc_lambda": ewc_lambda,
            "seed": config.seed,
            "fisher_summaries": fisher_summaries,
        }
    )

    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "labels_union_sorted": all_labels,
            "feature_cols": feature_cols,
            "config": copy.deepcopy(config.__dict__),
            "metrics": metrics,
            "history": history,
            "fisher_summaries": fisher_summaries,
        },
        out_dir / "latest_model.pt",
    )
    with open(out_dir / "latest_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    with open(out_dir / "history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    return metrics


def run_joint_upper_bound(config: ExperimentConfig) -> Dict[str, Any]:
    """Train once on the union of all task data as a joint-training upper bound."""

    set_seed(config.seed)
    device = select_device(config.device)
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    files = get_merged_files(config.resolved_dataset_sources())
    file_splits = split_files(
        files=files,
        train_ratio=config.file_split["train_ratio"],
        val_ratio=config.file_split["val_ratio"],
    )
    tasks, feature_cols, all_labels = _build_task_runtimes(config, file_splits, device)
    n_classes = len(all_labels)

    model = ContinualMamba(
        input_dim=len(feature_cols),
        num_classes=n_classes,
        d_model=int(config.model["d_model"]),
        seq_len=int(config.model["seq_len"]),
        ssm_layers=int(config.model["ssm_layers"]),
        kan_hidden=int(config.model["kan_hidden"]),
        kan_grid=int(config.model["kan_grid"]),
        dropout=float(config.model["dropout"]),
        variant=str(config.model.get("variant", "mamba_kan")),
    ).to(device)

    x_train = np.concatenate([task.data.x_train for task in tasks], axis=0)
    y_train = np.concatenate([task.data.y_train for task in tasks], axis=0)
    batch_size = int(config.training["batch_size"])
    num_workers = int(config.training["num_workers"])
    train_loader = make_loader(x_train, y_train, batch_size, num_workers, shuffle=True)
    class_w = _class_weights(y_train, n_classes, device=device)
    criterion = nn.CrossEntropyLoss(
        weight=class_w,
        label_smoothing=float(config.training["label_smoothing"]),
    )
    optimizer = AdamW(
        model.parameters(),
        lr=float(config.training["lr"]),
        weight_decay=float(config.training["weight_decay"]),
    )
    epochs = int(config.training.get("joint_epochs", config.training.get("epochs_per_task", 6)))
    scheduler = _scheduler_for(
        optimizer,
        str(config.training.get("scheduler", "none")),
        epochs,
        int(config.training.get("warmup_epochs", 0)),
    )
    history: list[dict[str, Any]] = []

    for epoch in range(epochs):
        train_loss = train_epoch(
            model=model,
            loader=train_loader,
            optimizer=optimizer,
            criterion=criterion,
            device=device,
            grad_clip_norm=float(config.training["grad_clip_norm"]),
            label_smoothing=float(config.training["label_smoothing"]),
        )
        vals = [
            evaluate(model, task.val_loader, device, active_class_ids=task.active_class_ids)
            for task in tasks
        ]
        if scheduler is not None:
            scheduler.step()
        history.append(
            {
                "epoch": epoch + 1,
                "train_loss": train_loss,
                "mean_val_accuracy": float(np.mean([v.accuracy for v in vals])),
                "mean_val_macro_f1": float(np.mean([v.macro_f1 for v in vals])),
                "lr": optimizer.param_groups[0]["lr"],
            }
        )

    final_results = _evaluate_seen_tasks(model, tasks, len(tasks), device)
    acc_matrix = [[r.accuracy for r in final_results]]
    f1_matrix = [[r.macro_f1 for r in final_results]]
    latency_matrix = [[r.latency_ms_per_sample for r in final_results]]
    metrics = {
        "num_tasks": len(tasks),
        "task_names": [task.name for task in tasks],
        "joint_training_upper_bound": True,
        "accuracy_matrix": acc_matrix,
        "macro_f1_matrix": f1_matrix,
        "latency_matrix": latency_matrix,
        "average_accuracy_ak": float(np.mean(acc_matrix[-1])),
        "average_macro_f1_final": float(np.mean(f1_matrix[-1])),
        "num_features": len(feature_cols),
        "num_classes_union": n_classes,
        "device": str(device),
        "continual_method": "joint_upper_bound",
        "seed": config.seed,
    }
    for idx, task in enumerate(tasks):
        metrics[f"{task.name}_test_acc_after_final"] = acc_matrix[-1][idx]
        metrics[f"{task.name}_test_macro_f1_after_final"] = f1_matrix[-1][idx]
        metrics[f"{task.name}_latency_ms_per_sample_after_final"] = latency_matrix[-1][idx]

    torch.save(
        {
            "model_state_dict": model.state_dict(),
            "labels_union_sorted": all_labels,
            "feature_cols": feature_cols,
            "config": copy.deepcopy(config.__dict__),
            "metrics": metrics,
            "history": history,
        },
        out_dir / "latest_model.pt",
    )
    with open(out_dir / "latest_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    with open(out_dir / "history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    return metrics
