from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class DatasetSource:
    dataset_root: str
    merged_csv_subdir: str = "MERGED_CSV"
    file_pattern: str = "Merged*.csv"


@dataclass
class TaskSpec:
    name: str
    labels: List[str]


@dataclass
class ExperimentConfig:
    output_dir: str
    seed: int
    device: str
    file_split: Dict[str, float]
    max_samples_per_split: Dict[str, int]
    training: Dict[str, float]
    model: Dict[str, float]
    ewc: Dict[str, float]
    phase_labels: Dict[str, List[str]] | None = None
    tasks: List[TaskSpec] | None = None
    continual: Dict[str, Any] | None = None
    dataset_root: str | None = None
    merged_csv_subdir: str = "MERGED_CSV"
    merged_file_pattern: str = "Merged*.csv"
    dataset_sources: List[DatasetSource] | None = None

    @staticmethod
    def load(path: str | Path) -> "ExperimentConfig":
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        if "dataset_sources" in raw and raw["dataset_sources"] is not None:
            raw["dataset_sources"] = [DatasetSource(**src) for src in raw["dataset_sources"]]
        if "tasks" in raw and raw["tasks"] is not None:
            raw["tasks"] = [TaskSpec(**task) for task in raw["tasks"]]
        return ExperimentConfig(**raw)

    def resolved_tasks(self) -> List[TaskSpec]:
        if self.tasks:
            return self.tasks
        if self.phase_labels:
            return [
                TaskSpec(name=name, labels=labels)
                for name, labels in self.phase_labels.items()
            ]
        raise ValueError("Provide `tasks` or legacy `phase_labels` in config.")

    def resolved_dataset_sources(self) -> List[Dict[str, str]]:
        if self.dataset_sources:
            return [
                {
                    "dataset_root": src.dataset_root,
                    "merged_csv_subdir": src.merged_csv_subdir,
                    "file_pattern": src.file_pattern,
                }
                for src in self.dataset_sources
            ]
        if not self.dataset_root:
            raise ValueError("Provide `dataset_root` or non-empty `dataset_sources` in config.")
        return [
            {
                "dataset_root": self.dataset_root,
                "merged_csv_subdir": self.merged_csv_subdir,
                "file_pattern": self.merged_file_pattern,
            }
        ]
