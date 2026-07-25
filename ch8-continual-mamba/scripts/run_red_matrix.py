from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from continual_mamba.config import ExperimentConfig  # noqa: E402
from continual_mamba.train import run_experiment, run_joint_upper_bound  # noqa: E402


METHODS = [
    {"name": "finetune", "method": "finetune", "ewc_lambda": 0.0, "buffer_size": 0},
    {"name": "ewc", "method": "ewc", "ewc_lambda": 5.0, "buffer_size": 0},
    {"name": "er_ewc", "method": "er", "ewc_lambda": 5.0, "buffer_size": 10000},
    {"name": "erace_ewc", "method": "er_ace", "ewc_lambda": 5.0, "buffer_size": 10000},
    {"name": "derpp_ewc", "method": "derpp", "ewc_lambda": 5.0, "buffer_size": 10000},
    {"name": "lwf", "method": "lwf", "ewc_lambda": 0.0, "buffer_size": 0},
    {"name": "cfa_ewc", "method": "ewc", "ewc_lambda": 5.0, "buffer_size": 0, "fisher_weighting": "class_frequency"},
]


def write_status(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the red-checklist 4-task matrix with resume/skips")
    parser.add_argument("--config", type=str, default="configs/exp_ciciot_4task_mamba_kan_er_ewc.json")
    parser.add_argument("--output-dir", type=str, default="outputs/red_matrix_ciciot_4task")
    parser.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])
    parser.add_argument("--methods", type=str, nargs="*", default=None)
    parser.add_argument("--include-joint", action="store_true")
    parser.add_argument("--joint-epochs", type=int, default=24)
    args = parser.parse_args()

    base = ExperimentConfig.load(args.config)
    root = Path(args.output_dir)
    root.mkdir(parents=True, exist_ok=True)
    selected = [m for m in METHODS if args.methods is None or m["name"] in set(args.methods)]
    rows: list[dict[str, object]] = []

    for method in selected:
        for seed in args.seeds:
            out_dir = root / str(method["name"]) / f"seed_{seed}"
            metrics_path = out_dir / "latest_metrics.json"
            row = {"run": method["name"], "seed": seed, "path": str(out_dir)}
            if metrics_path.exists():
                row["status"] = "skipped_existing"
                rows.append(row)
                write_status(root / "status.csv", rows)
                continue

            config = ExperimentConfig.load(args.config)
            config.seed = int(seed)
            config.output_dir = str(out_dir)
            if config.continual is None:
                config.continual = {}
            config.continual["method"] = method["method"]
            config.continual["buffer_size"] = method["buffer_size"]
            config.ewc["lambda"] = method["ewc_lambda"]
            if "fisher_weighting" in method:
                config.ewc["fisher_weighting"] = method["fisher_weighting"]
            try:
                metrics = run_experiment(config)
                row["status"] = "completed"
                row["average_accuracy_ak"] = metrics.get("average_accuracy_ak")
                row["bwt"] = metrics.get("bwt")
                row["average_forgetting"] = metrics.get("average_forgetting")
            except Exception as exc:
                row["status"] = "failed"
                row["error"] = repr(exc)
                rows.append(row)
                write_status(root / "status.csv", rows)
                raise
            rows.append(row)
            write_status(root / "status.csv", rows)

    if args.include_joint:
        for seed in args.seeds:
            out_dir = root / "joint_upper" / f"seed_{seed}"
            metrics_path = out_dir / "latest_metrics.json"
            row = {"run": "joint_upper", "seed": seed, "path": str(out_dir)}
            if metrics_path.exists():
                row["status"] = "skipped_existing"
                rows.append(row)
                write_status(root / "status.csv", rows)
                continue
            config = ExperimentConfig.load(args.config)
            config.seed = int(seed)
            config.output_dir = str(out_dir)
            config.training["joint_epochs"] = int(args.joint_epochs)
            metrics = run_joint_upper_bound(config)
            row["status"] = "completed"
            row["average_accuracy_ak"] = metrics.get("average_accuracy_ak")
            rows.append(row)
            write_status(root / "status.csv", rows)

    with open(root / "status.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
