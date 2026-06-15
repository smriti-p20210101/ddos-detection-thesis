from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch.optim import AdamW
from torch.utils.data import DataLoader, TensorDataset


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from continual_mamba.data import get_merged_files, split_files  # noqa: E402
from continual_mamba.model import ContinualMamba  # noqa: E402
from continual_mamba.train import select_device, set_seed  # noqa: E402


REFERENCE_TABLES = {
    "CICIoT2022": [
        {"method": "RF", "accuracy": 0.8754, "precision": 0.8278, "recall": 0.8266, "f1": 0.8271},
        {"method": "CNN", "accuracy": 0.8165, "precision": 0.7749, "recall": 0.7380, "f1": 0.7560},
        {"method": "LSTM", "accuracy": 0.7916, "precision": 0.7567, "recall": 0.7030, "f1": 0.7288},
        {"method": "YaTC", "accuracy": 0.9974, "precision": 0.9975, "recall": 0.9974, "f1": 0.9974},
        {"method": "NetMamba", "accuracy": 0.9928, "precision": 0.9931, "recall": 0.9928, "f1": 0.9929},
        {"method": "MAMBA-KAN (reported)", "accuracy": 0.9989, "precision": 0.9990, "recall": 0.9990, "f1": 0.9990},
    ],
    "CICIDS2017": [
        {"method": "RF", "accuracy": 0.9983, "precision": 0.9059, "recall": 0.8732, "f1": 0.8892},
        {"method": "CNN", "accuracy": 0.9979, "precision": 0.8935, "recall": 0.8256, "f1": 0.8582},
        {"method": "LSTM", "accuracy": 0.9976, "precision": 0.8282, "recall": 0.8209, "f1": 0.8245},
        {"method": "YaTC", "accuracy": 0.9731, "precision": 0.9733, "recall": 0.9731, "f1": 0.9731},
        {"method": "NetMamba", "accuracy": 0.9624, "precision": 0.9626, "recall": 0.9625, "f1": 0.9625},
        {"method": "MAMBA-KAN (reported)", "accuracy": 0.9653, "precision": 0.9654, "recall": 0.9654, "f1": 0.9654},
    ],
    "USTC-TFC2016": [
        {"method": "RF", "accuracy": 0.9017, "precision": 0.8864, "recall": 0.8745, "f1": 0.8820},
        {"method": "CNN", "accuracy": 0.8722, "precision": 0.8810, "recall": 0.8441, "f1": 0.8621},
        {"method": "LSTM", "accuracy": 0.8702, "precision": 0.8865, "recall": 0.8546, "f1": 0.8702},
        {"method": "YaTC", "accuracy": 0.9695, "precision": 0.9695, "recall": 0.9695, "f1": 0.9695},
        {"method": "NetMamba", "accuracy": 0.9966, "precision": 0.9967, "recall": 0.9966, "f1": 0.9966},
        {"method": "MAMBA-KAN (reported)", "accuracy": 0.9969, "precision": 0.9971, "recall": 0.9969, "f1": 0.9969},
    ],
    "CrossPlatform(Android)": [
        {"method": "RF", "accuracy": 0.9107, "precision": 0.9127, "recall": 0.9085, "f1": 0.9089},
        {"method": "CNN", "accuracy": 0.6489, "precision": 0.6774, "recall": 0.6599, "f1": 0.6685},
        {"method": "LSTM", "accuracy": 0.7934, "precision": 0.8126, "recall": 0.7946, "f1": 0.8034},
        {"method": "YaTC", "accuracy": 0.8952, "precision": 0.8989, "recall": 0.8952, "f1": 0.8952},
        {"method": "NetMamba", "accuracy": 0.9094, "precision": 0.9133, "recall": 0.9094, "f1": 0.9096},
        {"method": "MAMBA-KAN (reported)", "accuracy": 0.9162, "precision": 0.9190, "recall": 0.9162, "f1": 0.9164},
    ],
}

REFERENCE_ALIASES = {
    "cic-iot2022": "CICIoT2022",
    "ciciot2022": "CICIoT2022",
    "cicids2017": "CICIDS2017",
    "cic-ids2017": "CICIDS2017",
    "ustc-tfc2016": "USTC-TFC2016",
    "crossplatform(android)": "CrossPlatform(Android)",
    "crossplatform": "CrossPlatform(Android)",
}

DEFAULT_IGNORE_COLUMNS = {
    "Flow ID",
    "Source IP",
    "Destination IP",
    "Timestamp",
}


def _load_json(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _dataset_sources(config: dict[str, Any]) -> list[dict[str, str]]:
    if config.get("dataset_sources"):
        return [
            {
                "dataset_root": src["dataset_root"],
                "merged_csv_subdir": src.get("merged_csv_subdir", "MERGED_CSV"),
                "file_pattern": src.get("file_pattern", "Merged*.csv"),
            }
            for src in config["dataset_sources"]
        ]
    return [
        {
            "dataset_root": config["dataset_root"],
            "merged_csv_subdir": config.get("merged_csv_subdir", "MERGED_CSV"),
            "file_pattern": config.get("merged_file_pattern", config.get("file_pattern", "Merged*.csv")),
        }
    ]


def _limit(config: dict[str, Any], split: str) -> int | None:
    value = int(config.get("max_samples_per_split", {}).get(split, 0))
    return value if value > 0 else None


def _reference_key(name: str | None) -> str | None:
    if not name:
        return None
    key = str(name).strip()
    return REFERENCE_ALIASES.get(key.lower(), key)


def _reference_rows(config: dict[str, Any]) -> list[dict[str, Any]]:
    reference_name = _reference_key(config.get("reference_dataset") or config.get("dataset_name"))
    if reference_name is None:
        return []
    rows = REFERENCE_TABLES.get(reference_name, [])
    return [
        {
            **row,
            "average": "reported",
            "source": f"Zhao and Zhang 2025 Table 4 ({reference_name})",
        }
        for row in rows
    ]


def _infer_labels(files: list[Path], label_col: str) -> list[str]:
    labels: set[str] = set()
    for path in files:
        for chunk in pd.read_csv(path, chunksize=200_000):
            chunk.columns = chunk.columns.str.strip()
            if label_col not in chunk.columns:
                raise KeyError(f"Missing label column `{label_col}` in {path}.")
            labels.update(chunk[label_col].dropna().astype(str).unique().tolist())
    if not labels:
        raise RuntimeError(f"No labels found in column `{label_col}`.")
    return sorted(labels)


def _read_split(
    files: list[Path],
    label_col: str,
    labels: set[str],
    max_samples: int | None,
    seed: int,
    feature_cols: list[str] | None = None,
    ignore_columns: set[str] | None = None,
) -> tuple[np.ndarray, np.ndarray, list[str], dict[str, int]]:
    rng = np.random.default_rng(seed)
    x_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []
    counts: Counter[str] = Counter()
    total = 0
    ignore_columns = ignore_columns or set()

    for path in files:
        if max_samples is not None and total >= max_samples:
            break
        for chunk in pd.read_csv(path, chunksize=200_000):
            chunk.columns = chunk.columns.str.strip()
            if label_col not in chunk.columns:
                raise KeyError(f"Missing label column `{label_col}` in {path}.")
            chunk = chunk.dropna(subset=[label_col])
            chunk[label_col] = chunk[label_col].astype(str)
            chunk = chunk[chunk[label_col].isin(labels)]
            if chunk.empty:
                continue
            if feature_cols is None:
                feature_cols = [
                    col
                    for col in chunk.columns
                    if col != label_col and col not in ignore_columns
                ]

            feat_df = chunk[feature_cols].apply(pd.to_numeric, errors="coerce")
            feat_df = feat_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            feat_df = feat_df.clip(-1e9, 1e9)
            chunk_x = feat_df.astype(np.float32).to_numpy()
            chunk_y = chunk[label_col].to_numpy()

            if max_samples is not None:
                remaining = max_samples - total
                if remaining <= 0:
                    break
                if len(chunk_x) > remaining:
                    idx = rng.choice(len(chunk_x), size=remaining, replace=False)
                    chunk_x = chunk_x[idx]
                    chunk_y = chunk_y[idx]

            x_parts.append(chunk_x)
            y_parts.append(chunk_y)
            counts.update(chunk_y.tolist())
            total += len(chunk_y)

            if max_samples is not None and total >= max_samples:
                break

    if not x_parts or feature_cols is None:
        raise RuntimeError("No rows were loaded. Check dataset path, label column, and label names.")

    return np.concatenate(x_parts), np.concatenate(y_parts), feature_cols, dict(counts)


def _count_filtered_rows(files: list[Path], label_col: str, labels: set[str]) -> int:
    total = 0
    for path in files:
        for chunk in pd.read_csv(path, chunksize=200_000):
            chunk.columns = chunk.columns.str.strip()
            if label_col not in chunk.columns:
                raise KeyError(f"Missing label column `{label_col}` in {path}.")
            chunk = chunk.dropna(subset=[label_col])
            chunk[label_col] = chunk[label_col].astype(str)
            total += int(chunk[chunk[label_col].isin(labels)].shape[0])
    return total


def _read_order_range(
    files: list[Path],
    label_col: str,
    labels: set[str],
    start_frac: float,
    end_frac: float,
    max_samples: int | None,
    seed: int,
    feature_cols: list[str] | None = None,
    ignore_columns: set[str] | None = None,
) -> tuple[np.ndarray, np.ndarray, list[str], dict[str, int]]:
    rng = np.random.default_rng(seed)
    total_rows = _count_filtered_rows(files, label_col, labels)
    start_idx = int(total_rows * start_frac)
    end_idx = int(total_rows * end_frac)
    end_idx = min(max(end_idx, start_idx), total_rows)

    x_parts: list[np.ndarray] = []
    y_parts: list[np.ndarray] = []
    counts: Counter[str] = Counter()
    seen = 0
    loaded = 0
    ignore_columns = ignore_columns or set()

    for path in files:
        if max_samples is not None and loaded >= max_samples:
            break
        for chunk in pd.read_csv(path, chunksize=200_000):
            chunk.columns = chunk.columns.str.strip()
            if label_col not in chunk.columns:
                raise KeyError(f"Missing label column `{label_col}` in {path}.")
            chunk = chunk.dropna(subset=[label_col])
            chunk[label_col] = chunk[label_col].astype(str)
            chunk = chunk[chunk[label_col].isin(labels)]
            if chunk.empty:
                continue

            chunk_start = seen
            chunk_end = seen + len(chunk)
            seen = chunk_end
            if chunk_end <= start_idx or chunk_start >= end_idx:
                continue

            rel_start = max(start_idx - chunk_start, 0)
            rel_end = min(end_idx - chunk_start, len(chunk))
            chunk = chunk.iloc[rel_start:rel_end]
            if chunk.empty:
                continue

            if feature_cols is None:
                feature_cols = [
                    col
                    for col in chunk.columns
                    if col != label_col and col not in ignore_columns
                ]

            feat_df = chunk[feature_cols].apply(pd.to_numeric, errors="coerce")
            feat_df = feat_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            feat_df = feat_df.clip(-1e9, 1e9)
            chunk_x = feat_df.astype(np.float32).to_numpy()
            chunk_y = chunk[label_col].to_numpy()

            if max_samples is not None:
                remaining = max_samples - loaded
                if remaining <= 0:
                    break
                if len(chunk_x) > remaining:
                    idx = rng.choice(len(chunk_x), size=remaining, replace=False)
                    chunk_x = chunk_x[idx]
                    chunk_y = chunk_y[idx]

            x_parts.append(chunk_x)
            y_parts.append(chunk_y)
            counts.update(chunk_y.tolist())
            loaded += len(chunk_y)

            if max_samples is not None and loaded >= max_samples:
                break

    if not x_parts or feature_cols is None:
        raise RuntimeError("No rows were loaded. Check dataset path, label column, and label names.")

    return np.concatenate(x_parts), np.concatenate(y_parts), feature_cols, dict(counts)


def _cap_rows(
    x: np.ndarray,
    y: np.ndarray,
    max_samples: int | None,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    if max_samples is None or len(y) <= max_samples:
        return x, y
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(y), size=max_samples, replace=False)
    return x[idx], y[idx]


def _encode(y: np.ndarray, label_to_id: dict[str, int]) -> np.ndarray:
    return np.array([label_to_id[str(label)] for label in y], dtype=np.int64)


def _loader(x: np.ndarray, y: np.ndarray, batch_size: int, num_workers: int, shuffle: bool) -> DataLoader:
    dataset = TensorDataset(torch.from_numpy(x), torch.from_numpy(y))
    return DataLoader(dataset, batch_size=batch_size, shuffle=shuffle, num_workers=num_workers, pin_memory=True)


def _class_weights(y: np.ndarray, num_classes: int, device: torch.device) -> torch.Tensor:
    counts = np.bincount(y, minlength=num_classes).astype(np.float64)
    counts[counts == 0] = 1.0
    weights = 1.0 / np.sqrt(counts)
    weights = weights / np.mean(weights)
    weights = np.clip(weights, 0.25, 4.0)
    return torch.tensor(weights, dtype=torch.float32, device=device)


def _train_epoch(
    model: torch.nn.Module,
    loader: DataLoader,
    optimizer: torch.optim.Optimizer,
    device: torch.device,
    class_weights: torch.Tensor | None,
    label_smoothing: float,
    grad_clip_norm: float,
) -> float:
    model.train()
    losses: list[float] = []
    for x, y in loader:
        x = x.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        optimizer.zero_grad(set_to_none=True)
        loss = F.cross_entropy(model(x), y, weight=class_weights, label_smoothing=label_smoothing)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), grad_clip_norm)
        optimizer.step()
        losses.append(float(loss.item()))
    return float(np.mean(losses))


def _predict(model: torch.nn.Module, loader: DataLoader, device: torch.device) -> tuple[np.ndarray, np.ndarray, float]:
    model.eval()
    y_true: list[np.ndarray] = []
    y_pred: list[np.ndarray] = []
    sample_count = 0
    start = time.perf_counter()
    with torch.no_grad():
        for x, y in loader:
            x = x.to(device, non_blocking=True)
            logits = model(x)
            pred = torch.argmax(logits, dim=1).cpu().numpy()
            y_true.append(y.numpy())
            y_pred.append(pred)
            sample_count += int(x.shape[0])
    if device.type == "cuda":
        torch.cuda.synchronize()
    elapsed = time.perf_counter() - start
    latency_ms = elapsed * 1000.0 / max(sample_count, 1)
    return np.concatenate(y_true), np.concatenate(y_pred), float(latency_ms)


def _metrics(model: torch.nn.Module, loader: DataLoader, device: torch.device) -> dict[str, float]:
    y_true, y_pred, latency = _predict(model, loader, device)
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_macro": float(precision_score(y_true, y_pred, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_true, y_pred, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "precision_weighted": float(precision_score(y_true, y_pred, average="weighted", zero_division=0)),
        "recall_weighted": float(recall_score(y_true, y_pred, average="weighted", zero_division=0)),
        "f1_weighted": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "latency_ms_per_sample": latency,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    keys = sorted({key for row in rows for key in row})
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(rows)


def _tex_escape(value: Any) -> str:
    return str(value).replace("\\", "\\textbackslash{}").replace("_", "\\_").replace("&", "\\&")


def _write_comparison_tex(path: Path, rows: list[dict[str, Any]]) -> None:
    raw_dataset_name = str(rows[0].get("comparison_dataset", "static dataset")) if rows else "static dataset"
    caption_dataset_name = _tex_escape(raw_dataset_name)
    label_dataset_name = (
        raw_dataset_name.lower()
        .replace(" ", "-")
        .replace("(", "")
        .replace(")", "")
        .replace("/", "-")
    )
    has_reference = any("Zhao and Zhang" in str(row.get("source", "")) for row in rows)
    caption = (
        f"Matched static {caption_dataset_name} comparison against the reported MAMBA-KAN study."
        if has_reference
        else f"Static {caption_dataset_name} local benchmark results."
    )
    lines = [
        "\\begin{table}[t]",
        "\\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{tab:{label_dataset_name}-static-reference}}",
        "\\begin{tabular}{lccccc}",
        "\\hline",
        "Method & Avg. & AC & PR & RC & F1 \\\\",
        "\\hline",
    ]
    for row in rows:
        lines.append(
            f"{_tex_escape(row['method'])} & {_tex_escape(row['average'])} & "
            f"{row['accuracy']:.4f} & {row['precision']:.4f} & "
            f"{row['recall']:.4f} & {row['f1']:.4f} \\\\"
        )
    lines.extend(["\\hline", "\\end{tabular}", "\\end{table}", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def run_static_benchmark(config: dict[str, Any]) -> dict[str, Any]:
    set_seed(int(config.get("seed", 42)))
    device = select_device(str(config.get("device", "cuda")))
    out_dir = Path(config.get("output_dir", "outputs/static_benchmark"))
    out_dir.mkdir(parents=True, exist_ok=True)
    dataset_name = str(config.get("dataset_name", "static-dataset"))

    files = get_merged_files(_dataset_sources(config))
    split_cfg = config.get("file_split", {})
    train_ratio = float(split_cfg.get("train_ratio", 0.8))
    val_ratio = float(split_cfg.get("val_ratio", 0.1))

    label_col = str(config.get("label_col", "Label"))
    ignore_columns = DEFAULT_IGNORE_COLUMNS | set(config.get("ignore_columns", []))
    label_order = config.get("labels") or _infer_labels(files, label_col)
    label_order = [str(label) for label in label_order]
    label_to_id = {label: idx for idx, label in enumerate(label_order)}
    split_mode = str(config.get("split_mode", "row_order" if config.get("row_order_split", len(files) < 3) else "file_order"))
    split_mode = split_mode.lower()
    use_row_order_split = split_mode == "row_order"

    if split_mode == "stratified":
        max_total = config.get("max_total_samples")
        x_all, y_all_raw, feature_cols, _ = _read_split(
            files,
            label_col,
            set(label_order),
            int(max_total) if max_total else None,
            int(config.get("seed", 42)),
            ignore_columns=ignore_columns,
        )
        x_train_val, x_test, y_train_val_raw, y_test_raw = train_test_split(
            x_all,
            y_all_raw,
            test_size=max(1.0 - train_ratio - val_ratio, 0.0001),
            random_state=int(config.get("seed", 42)),
            stratify=y_all_raw,
        )
        val_size = val_ratio / max(train_ratio + val_ratio, 1e-9)
        x_train, x_val, y_train_raw, y_val_raw = train_test_split(
            x_train_val,
            y_train_val_raw,
            test_size=val_size,
            random_state=int(config.get("seed", 42)) + 1,
            stratify=y_train_val_raw,
        )
        x_train, y_train_raw = _cap_rows(x_train, y_train_raw, _limit(config, "train"), int(config.get("seed", 42)) + 2)
        x_val, y_val_raw = _cap_rows(x_val, y_val_raw, _limit(config, "val"), int(config.get("seed", 42)) + 3)
        x_test, y_test_raw = _cap_rows(x_test, y_test_raw, _limit(config, "test"), int(config.get("seed", 42)) + 4)
        train_counts = dict(Counter(y_train_raw.tolist()))
        val_counts = dict(Counter(y_val_raw.tolist()))
        test_counts = dict(Counter(y_test_raw.tolist()))
        protocol = f"stratified_{round(train_ratio * 100)}_{round(val_ratio * 100)}_{round((1.0 - train_ratio - val_ratio) * 100)}"
    elif use_row_order_split:
        train_end = train_ratio
        val_end = train_ratio + val_ratio
        x_train, y_train_raw, feature_cols, train_counts = _read_order_range(
            files,
            label_col,
            set(label_order),
            0.0,
            train_end,
            _limit(config, "train"),
            int(config.get("seed", 42)),
            ignore_columns=ignore_columns,
        )
        x_val, y_val_raw, _, val_counts = _read_order_range(
            files,
            label_col,
            set(label_order),
            train_end,
            val_end,
            _limit(config, "val"),
            int(config.get("seed", 42)) + 1,
            feature_cols=feature_cols,
            ignore_columns=ignore_columns,
        )
        x_test, y_test_raw, _, test_counts = _read_order_range(
            files,
            label_col,
            set(label_order),
            val_end,
            1.0,
            _limit(config, "test"),
            int(config.get("seed", 42)) + 2,
            feature_cols=feature_cols,
            ignore_columns=ignore_columns,
        )
        protocol = f"row_order_{round(train_ratio * 100)}_{round(val_ratio * 100)}_{round((1.0 - train_ratio - val_ratio) * 100)}"
    else:
        file_splits = split_files(files, train_ratio=train_ratio, val_ratio=val_ratio)
        x_train, y_train_raw, feature_cols, train_counts = _read_split(
            file_splits["train"],
            label_col,
            set(label_order),
            _limit(config, "train"),
            int(config.get("seed", 42)),
            ignore_columns=ignore_columns,
        )
        x_val, y_val_raw, _, val_counts = _read_split(
            file_splits["val"],
            label_col,
            set(label_order),
            _limit(config, "val"),
            int(config.get("seed", 42)) + 1,
            feature_cols=feature_cols,
            ignore_columns=ignore_columns,
        )
        x_test, y_test_raw, _, test_counts = _read_split(
            file_splits["test"],
            label_col,
            set(label_order),
            _limit(config, "test"),
            int(config.get("seed", 42)) + 2,
            feature_cols=feature_cols,
            ignore_columns=ignore_columns,
        )
        protocol = f"file_order_{round(train_ratio * 100)}_{round(val_ratio * 100)}_{round((1.0 - train_ratio - val_ratio) * 100)}"

    y_train = _encode(y_train_raw, label_to_id)
    y_val = _encode(y_val_raw, label_to_id)
    y_test = _encode(y_test_raw, label_to_id)

    scaler = StandardScaler()
    x_train = scaler.fit_transform(x_train).astype(np.float32)
    x_val = scaler.transform(x_val).astype(np.float32)
    x_test = scaler.transform(x_test).astype(np.float32)

    training = config.get("training", {})
    model_cfg = config.get("model", {})
    batch_size = int(training.get("batch_size", 512))
    num_workers = int(training.get("num_workers", 0))
    train_loader = _loader(x_train, y_train, batch_size, num_workers, shuffle=True)
    val_loader = _loader(x_val, y_val, batch_size, num_workers, shuffle=False)
    test_loader = _loader(x_test, y_test, batch_size, num_workers, shuffle=False)

    model = ContinualMamba(
        input_dim=x_train.shape[1],
        num_classes=len(label_order),
        d_model=int(model_cfg.get("d_model", 96)),
        seq_len=int(model_cfg.get("seq_len", 10)),
        ssm_layers=int(model_cfg.get("ssm_layers", 2)),
        kan_hidden=int(model_cfg.get("kan_hidden", 96)),
        kan_grid=int(model_cfg.get("kan_grid", 8)),
        dropout=float(model_cfg.get("dropout", 0.1)),
        variant=str(model_cfg.get("variant", "mamba_kan")),
    ).to(device)

    optimizer = AdamW(
        model.parameters(),
        lr=float(training.get("lr", 0.001)),
        weight_decay=float(training.get("weight_decay", 0.0001)),
    )
    weights = (
        _class_weights(y_train, len(label_order), device)
        if bool(training.get("class_weights", True))
        else None
    )
    label_smoothing = float(training.get("label_smoothing", 0.0))
    grad_clip_norm = float(training.get("grad_clip_norm", 1.0))

    history: list[dict[str, float]] = []
    best_state = None
    best_val_f1 = -1.0
    epochs = int(training.get("epochs", 50))
    for epoch in range(epochs):
        loss = _train_epoch(
            model,
            train_loader,
            optimizer,
            device,
            weights,
            label_smoothing,
            grad_clip_norm,
        )
        val_metrics = _metrics(model, val_loader, device)
        row = {"epoch": float(epoch + 1), "train_loss": loss, **{f"val_{k}": v for k, v in val_metrics.items()}}
        history.append(row)
        if val_metrics["f1_macro"] > best_val_f1:
            best_val_f1 = val_metrics["f1_macro"]
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
        print(
            f"epoch {epoch + 1:03d}/{epochs} "
            f"loss={loss:.4f} val_acc={val_metrics['accuracy']:.4f} "
            f"val_f1_macro={val_metrics['f1_macro']:.4f}"
        )

    if best_state is not None:
        model.load_state_dict(best_state)

    test_metrics = _metrics(model, test_loader, device)
    metrics: dict[str, Any] = {
        "dataset": dataset_name,
        "protocol": protocol,
        "variant": str(model_cfg.get("variant", "mamba_kan")),
        "seed": int(config.get("seed", 42)),
        "device": str(device),
        "num_features": int(x_train.shape[1]),
        "num_classes": int(len(label_order)),
        "labels": label_order,
        "train_samples": int(len(y_train)),
        "val_samples": int(len(y_val)),
        "test_samples": int(len(y_test)),
        "train_label_counts": train_counts,
        "val_label_counts": val_counts,
        "test_label_counts": test_counts,
        **{f"test_{key}": value for key, value in test_metrics.items()},
    }

    with open(out_dir / "static_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    with open(out_dir / "history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)
    torch.save(model.state_dict(), out_dir / "static_best_model.pt")

    reference_rows = _reference_rows(config)
    comparison_dataset = str(config.get("reference_dataset") or dataset_name)
    comparison_rows = [{**row, "comparison_dataset": comparison_dataset} for row in reference_rows]
    comparison_rows.extend(
        [
            {
                "method": f"{metrics['variant']} (this work, macro)",
                "average": "macro",
                "accuracy": metrics["test_accuracy"],
                "precision": metrics["test_precision_macro"],
                "recall": metrics["test_recall_macro"],
                "f1": metrics["test_f1_macro"],
                "source": "local run",
                "comparison_dataset": comparison_dataset,
            },
            {
                "method": f"{metrics['variant']} (this work, weighted)",
                "average": "weighted",
                "accuracy": metrics["test_accuracy"],
                "precision": metrics["test_precision_weighted"],
                "recall": metrics["test_recall_weighted"],
                "f1": metrics["test_f1_weighted"],
                "source": "local run",
                "comparison_dataset": comparison_dataset,
            },
        ]
    )
    _write_csv(out_dir / "static_comparison.csv", comparison_rows)
    _write_comparison_tex(out_dir / "static_comparison.tex", comparison_rows)
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a static IDS benchmark for paper comparison.")
    parser.add_argument("--config", type=str, required=True, help="Path to static benchmark JSON config.")
    args = parser.parse_args()

    metrics = run_static_benchmark(_load_json(args.config))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
