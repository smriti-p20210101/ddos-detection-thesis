from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import torch
import torch.nn as nn


@dataclass
class ReplayBatch:
    x: torch.Tensor
    y: torch.Tensor
    logits: torch.Tensor | None


class ReplayBuffer:
    """Small class-balanced exemplar buffer for ER/DER-style baselines."""

    def __init__(self, max_size: int, seed: int) -> None:
        self.max_size = int(max_size)
        self.rng = np.random.default_rng(seed)
        self.x: np.ndarray | None = None
        self.y: np.ndarray | None = None
        self.logits: np.ndarray | None = None

    def __len__(self) -> int:
        if self.y is None:
            return 0
        return int(len(self.y))

    def add_examples(
        self,
        x: np.ndarray,
        y: np.ndarray,
        model: nn.Module | None,
        device: torch.device,
        batch_size: int,
        store_logits: bool,
    ) -> None:
        if self.max_size <= 0:
            return

        keep = self._balanced_indices(y, min(len(y), self.max_size))
        new_x = x[keep].astype(np.float32, copy=True)
        new_y = y[keep].astype(np.int64, copy=True)
        new_logits = None
        if store_logits and model is not None:
            new_logits = self._predict_logits(model, new_x, device, batch_size)

        if self.x is None:
            self.x = new_x
            self.y = new_y
            self.logits = new_logits
        else:
            self.x = np.concatenate([self.x, new_x], axis=0)
            self.y = np.concatenate([self.y, new_y], axis=0)
            if store_logits and self.logits is not None and new_logits is not None:
                self.logits = np.concatenate([self.logits, new_logits], axis=0)
            else:
                self.logits = None

        self._trim()

    def sample(self, batch_size: int, device: torch.device) -> ReplayBatch | None:
        if self.x is None or self.y is None or len(self.y) == 0 or batch_size <= 0:
            return None
        size = min(int(batch_size), len(self.y))
        idx = self.rng.choice(len(self.y), size=size, replace=len(self.y) < size)
        logits = None
        if self.logits is not None:
            logits = torch.from_numpy(self.logits[idx]).to(device=device, dtype=torch.float32)
        return ReplayBatch(
            x=torch.from_numpy(self.x[idx]).to(device=device, dtype=torch.float32),
            y=torch.from_numpy(self.y[idx]).to(device=device, dtype=torch.long),
            logits=logits,
        )

    def _trim(self) -> None:
        if self.y is None or len(self.y) <= self.max_size:
            return
        keep = self._balanced_indices(self.y, self.max_size)
        assert self.x is not None
        self.x = self.x[keep]
        self.y = self.y[keep]
        if self.logits is not None:
            self.logits = self.logits[keep]

    def _balanced_indices(self, y: np.ndarray, target_size: int) -> np.ndarray:
        labels = np.unique(y)
        per_class = max(target_size // max(len(labels), 1), 1)
        chosen = []
        leftovers = []
        for label in labels:
            idx = np.flatnonzero(y == label)
            self.rng.shuffle(idx)
            chosen.extend(idx[:per_class].tolist())
            leftovers.extend(idx[per_class:].tolist())
        remaining = target_size - len(chosen)
        if remaining > 0 and leftovers:
            leftovers_arr = np.array(leftovers, dtype=np.int64)
            extra = self.rng.choice(
                leftovers_arr,
                size=min(remaining, len(leftovers_arr)),
                replace=False,
            )
            chosen.extend(extra.tolist())
        chosen_arr = np.array(chosen[:target_size], dtype=np.int64)
        self.rng.shuffle(chosen_arr)
        return chosen_arr

    @staticmethod
    def _predict_logits(
        model: nn.Module,
        x: np.ndarray,
        device: torch.device,
        batch_size: int,
    ) -> np.ndarray:
        model.eval()
        outs = []
        with torch.no_grad():
            for start in range(0, len(x), batch_size):
                xb = torch.from_numpy(x[start : start + batch_size]).to(
                    device=device,
                    dtype=torch.float32,
                )
                outs.append(model(xb).detach().cpu().numpy())
        return np.concatenate(outs, axis=0).astype(np.float32)
