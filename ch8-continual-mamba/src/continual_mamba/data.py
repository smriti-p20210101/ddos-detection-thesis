from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler
from torch.utils.data import DataLoader, TensorDataset


LABEL_COL = "Label"


@dataclass
class PhaseData:
    x_train: np.ndarray
    y_train: np.ndarray
    x_val: np.ndarray
    y_val: np.ndarray
    x_test: np.ndarray
    y_test: np.ndarray


def get_merged_files(dataset_sources: List[Dict[str, str]]) -> List[Path]:
    all_files: List[Path] = []
    for src in dataset_sources:
        dataset_root = src["dataset_root"]
        merged_csv_subdir = src.get("merged_csv_subdir", "MERGED_CSV")
        file_pattern = src.get("file_pattern", "Merged*.csv")
        merged_dir = Path(dataset_root) / merged_csv_subdir
        files = sorted(merged_dir.glob(file_pattern))
        if not files:
            raise FileNotFoundError(
                f"No merged csv files found in: {merged_dir} (pattern: {file_pattern})"
            )
        all_files.extend(files)

    # Deduplicate in case overlapping sources point to the same files.
    deduped = sorted({f.resolve() for f in all_files})
    return deduped


def split_files(files: List[Path], train_ratio: float, val_ratio: float) -> Dict[str, List[Path]]:
    n = len(files)
    n_train = int(n * train_ratio)
    n_val = int(n * val_ratio)
    if n_train < 1 or n_val < 1 or (n - n_train - n_val) < 1:
        raise ValueError("Invalid file split ratios.")
    return {
        "train": files[:n_train],
        "val": files[n_train : n_train + n_val],
        "test": files[n_train + n_val :],
    }


def _sample_split(
    files: Iterable[Path],
    allowed_labels: set[str],
    max_samples: int,
    seed: int,
) -> Tuple[np.ndarray, np.ndarray, List[str]]:
    rng = np.random.default_rng(seed)
    x_parts: List[np.ndarray] = []
    y_parts: List[np.ndarray] = []
    feature_cols: List[str] | None = None
    count = 0

    for f in files:
        if count >= max_samples:
            break
        for chunk in pd.read_csv(f, chunksize=200_000):
            chunk = chunk.dropna(subset=[LABEL_COL])
            chunk = chunk[chunk[LABEL_COL].isin(allowed_labels)]
            if chunk.empty:
                continue
            if feature_cols is None:
                feature_cols = [c for c in chunk.columns if c != LABEL_COL]
            feat_df = chunk[feature_cols].apply(pd.to_numeric, errors="coerce")
            feat_df = feat_df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
            feat_df = feat_df.clip(-1e9, 1e9)
            chunk_x = feat_df.astype(np.float32).to_numpy()
            chunk_y = chunk[LABEL_COL].astype(str).to_numpy()

            if len(chunk_x) > 0:
                remaining = max_samples - count
                if len(chunk_x) > remaining:
                    idx = rng.choice(len(chunk_x), size=remaining, replace=False)
                    chunk_x = chunk_x[idx]
                    chunk_y = chunk_y[idx]
                x_parts.append(chunk_x)
                y_parts.append(chunk_y)
                count += len(chunk_x)
            if count >= max_samples:
                break

    if not x_parts:
        raise RuntimeError("No rows sampled for split. Check labels/dataset.")

    x = np.concatenate(x_parts, axis=0)
    y = np.concatenate(y_parts, axis=0)
    assert feature_cols is not None
    return x, y, feature_cols


def build_phase_data(
    file_splits: Dict[str, List[Path]],
    phase_labels: List[str],
    max_samples_per_split: Dict[str, int],
    phase_name: str,
    seed: int,
) -> Tuple[PhaseData, List[str]]:
    allowed = set(phase_labels)
    x_train, y_train_raw, feature_cols = _sample_split(
        file_splits["train"], allowed, _split_limit(max_samples_per_split, phase_name, "train"), seed
    )
    x_val, y_val_raw, _ = _sample_split(
        file_splits["val"], allowed, _split_limit(max_samples_per_split, phase_name, "val"), seed + 1
    )
    x_test, y_test_raw, _ = _sample_split(
        file_splits["test"], allowed, _split_limit(max_samples_per_split, phase_name, "test"), seed + 2
    )

    label_order = sorted(list(allowed))
    label_to_id = {lbl: i for i, lbl in enumerate(label_order)}
    y_train = np.array([label_to_id[x] for x in y_train_raw], dtype=np.int64)
    y_val = np.array([label_to_id[x] for x in y_val_raw], dtype=np.int64)
    y_test = np.array([label_to_id[x] for x in y_test_raw], dtype=np.int64)

    return (
        PhaseData(
            x_train=x_train,
            y_train=y_train,
            x_val=x_val,
            y_val=y_val,
            x_test=x_test,
            y_test=y_test,
        ),
        feature_cols,
    )


def _split_limit(max_samples_per_split: Dict[str, int], task_name: str, split: str) -> int:
    key = f"{task_name}_{split}"
    if key in max_samples_per_split:
        return int(max_samples_per_split[key])
    if split in max_samples_per_split:
        return int(max_samples_per_split[split])
    raise KeyError(
        f"Missing max_samples_per_split entry for `{key}`. "
        f"Provide `{key}` or a generic `{split}` value."
    )


def fit_scaler(x_train: np.ndarray) -> StandardScaler:
    scaler = StandardScaler()
    scaler.fit(x_train)
    return scaler


def apply_scaler(phase_data: PhaseData, scaler: StandardScaler) -> PhaseData:
    return PhaseData(
        x_train=scaler.transform(phase_data.x_train).astype(np.float32),
        y_train=phase_data.y_train,
        x_val=scaler.transform(phase_data.x_val).astype(np.float32),
        y_val=phase_data.y_val,
        x_test=scaler.transform(phase_data.x_test).astype(np.float32),
        y_test=phase_data.y_test,
    )


def make_loader(
    x: np.ndarray,
    y: np.ndarray,
    batch_size: int,
    num_workers: int,
    shuffle: bool,
) -> DataLoader:
    ds = TensorDataset(torch.from_numpy(x), torch.from_numpy(y))
    return DataLoader(
        ds,
        batch_size=batch_size,
        shuffle=shuffle,
        num_workers=num_workers,
        pin_memory=True,
        drop_last=False,
    )
