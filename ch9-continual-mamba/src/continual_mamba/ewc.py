from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import torch
import torch.nn as nn
import torch.nn.functional as F


@dataclass
class EWCState:
    fisher: Dict[str, torch.Tensor]
    params_star: Dict[str, torch.Tensor]


def compute_fisher(
    model: nn.Module,
    data_loader,
    criterion: nn.Module,
    device: torch.device,
    max_batches: int,
    active_class_ids: list[int] | None = None,
    local_map: torch.Tensor | None = None,
    label_smoothing: float = 0.0,
    class_weights_global: torch.Tensor | None = None,
) -> Dict[str, torch.Tensor]:
    model.eval()
    fisher = {
        n: torch.zeros_like(p, device=device)
        for n, p in model.named_parameters()
        if p.requires_grad
    }

    batches = 0
    for x, y in data_loader:
        x = x.to(device, non_blocking=True)
        y = y.to(device, non_blocking=True)
        model.zero_grad(set_to_none=True)
        logits = model(x)
        if active_class_ids is not None and local_map is not None:
            active = torch.tensor(active_class_ids, dtype=torch.long, device=device)
            weights = class_weights_global[active] if class_weights_global is not None else None
            loss = F.cross_entropy(
                logits[:, active],
                local_map[y],
                weight=weights,
                label_smoothing=label_smoothing,
            )
        else:
            loss = criterion(logits, y)
        loss.backward()
        for n, p in model.named_parameters():
            if p.grad is not None and p.requires_grad:
                fisher[n] += p.grad.detach() ** 2
        batches += 1
        if batches >= max_batches:
            break

    for n in fisher:
        fisher[n] /= max(batches, 1)
    return fisher


def consolidate(model: nn.Module, fisher: Dict[str, torch.Tensor]) -> EWCState:
    params_star = {
        n: p.detach().clone()
        for n, p in model.named_parameters()
        if p.requires_grad
    }
    return EWCState(fisher=fisher, params_star=params_star)


def ewc_penalty(model: nn.Module, state: EWCState) -> torch.Tensor:
    penalty = torch.tensor(0.0, device=next(model.parameters()).device)
    for n, p in model.named_parameters():
        if not p.requires_grad or n not in state.fisher:
            continue
        penalty = penalty + torch.sum(state.fisher[n] * (p - state.params_star[n]) ** 2)
    return penalty
