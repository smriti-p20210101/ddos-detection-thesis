from __future__ import annotations

import argparse
import copy
import csv
import json
import statistics
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from continual_mamba.config import ExperimentConfig  # noqa: E402
from continual_mamba.train import run_joint_upper_bound  # noqa: E402


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _summarize(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    numeric_keys = sorted({k for row in rows for k, v in row.items() if _is_number(v)})
    summary: dict[str, dict[str, float]] = {}
    for key in numeric_keys:
        values = [float(row[key]) for row in rows if key in row and _is_number(row[key])]
        summary[key] = {
            "mean": float(statistics.fmean(values)),
            "std": float(statistics.stdev(values)) if len(values) > 1 else 0.0,
            "n": float(len(values)),
        }
    return summary


def _write_summary_csv(path: Path, summary: dict[str, dict[str, float]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "mean", "std", "n"])
        writer.writeheader()
        for metric, stats in summary.items():
            writer.writerow({"metric": metric, **stats})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a joint-training upper bound")
    parser.add_argument("--config", type=str, required=True, help="Path to task-stream config json")
    parser.add_argument("--seeds", type=int, nargs="+", default=None, help="Optional multi-seed list")
    parser.add_argument("--output-dir", type=str, default=None, help="Override output directory")
    parser.add_argument("--joint-epochs", type=int, default=None, help="Override joint training epochs")
    args = parser.parse_args()

    base_config = ExperimentConfig.load(args.config)
    seeds = args.seeds or [base_config.seed]
    base_out = Path(args.output_dir or base_config.output_dir)
    base_out.mkdir(parents=True, exist_ok=True)

    rows = []
    for seed in seeds:
        config = copy.deepcopy(base_config)
        config.seed = int(seed)
        config.output_dir = str(base_out / f"seed_{seed}") if len(seeds) > 1 else str(base_out)
        if args.joint_epochs is not None:
            config.training["joint_epochs"] = int(args.joint_epochs)
        metrics = run_joint_upper_bound(config)
        rows.append(metrics)

    if len(rows) > 1:
        summary = _summarize(rows)
        with open(base_out / "joint_multiseed_metrics.json", "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2)
        with open(base_out / "joint_multiseed_summary.json", "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        _write_summary_csv(base_out / "joint_multiseed_summary.csv", summary)
        print(json.dumps(summary, indent=2))
    else:
        print(json.dumps(rows[0], indent=2))


if __name__ == "__main__":
    main()
