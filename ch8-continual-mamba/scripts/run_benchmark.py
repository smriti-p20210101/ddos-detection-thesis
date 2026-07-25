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
from continual_mamba.train import run_experiment  # noqa: E402


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _summarize(rows: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    numeric_keys = sorted({k for row in rows for k, v in row.items() if _is_number(v)})
    summary: dict[str, dict[str, float]] = {}
    for key in numeric_keys:
        values = [float(row[key]) for row in rows if key in row and _is_number(row[key])]
        if not values:
            continue
        summary[key] = {
            "mean": float(statistics.fmean(values)),
            "std": float(statistics.stdev(values)) if len(values) > 1 else 0.0,
            "n": float(len(values)),
        }
    return summary


def _write_rows_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    keys = sorted({k for row in rows for k in row.keys() if not isinstance(row.get(k), (list, dict))})
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in keys})


def _write_summary_csv(path: Path, summary: dict[str, dict[str, float]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["metric", "mean", "std", "n"])
        writer.writeheader()
        for metric, stats in summary.items():
            writer.writerow({"metric": metric, **stats})


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a multi-seed Continual-Mamba benchmark")
    parser.add_argument("--config", type=str, required=True, help="Path to config json")
    parser.add_argument("--seeds", type=int, nargs="+", required=True, help="Seed list")
    parser.add_argument("--output-dir", type=str, default=None, help="Override benchmark output directory")
    parser.add_argument("--method", type=str, default=None, help="Override continual method: finetune, ewc, er, er_ace, derpp, lwf, lwf_ewc")
    parser.add_argument("--ewc-lambda", type=float, default=None, help="Override EWC lambda")
    parser.add_argument("--buffer-size", type=int, default=None, help="Override replay buffer size")
    parser.add_argument("--replay-batch-size", type=int, default=None, help="Override replay batch size")
    parser.add_argument("--der-alpha", type=float, default=None, help="Override DER++ distillation weight")
    parser.add_argument("--lwf-alpha", type=float, default=None, help="Override LwF distillation weight")
    parser.add_argument("--lwf-temperature", type=float, default=None, help="Override LwF temperature")
    parser.add_argument("--fisher-weighting", type=str, default=None, help="Override Fisher weighting: none or class_frequency")
    args = parser.parse_args()

    base_config = ExperimentConfig.load(args.config)
    base_out = Path(args.output_dir or base_config.output_dir)
    base_out.mkdir(parents=True, exist_ok=True)

    rows = []
    for seed in args.seeds:
        config = copy.deepcopy(base_config)
        config.seed = int(seed)
        config.output_dir = str(base_out / f"seed_{seed}")
        if config.continual is None:
            config.continual = {}
        if args.method is not None:
            config.continual["method"] = args.method
        if args.ewc_lambda is not None:
            config.ewc["lambda"] = args.ewc_lambda
        if args.buffer_size is not None:
            config.continual["buffer_size"] = args.buffer_size
        if args.replay_batch_size is not None:
            config.continual["replay_batch_size"] = args.replay_batch_size
        if args.der_alpha is not None:
            config.continual["der_alpha"] = args.der_alpha
        if args.lwf_alpha is not None:
            config.continual["lwf_alpha"] = args.lwf_alpha
        if args.lwf_temperature is not None:
            config.continual["lwf_temperature"] = args.lwf_temperature
        if args.fisher_weighting is not None:
            config.ewc["fisher_weighting"] = args.fisher_weighting
        metrics = run_experiment(config)
        rows.append(metrics)

    summary = _summarize(rows)
    with open(base_out / "multiseed_metrics.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)
    with open(base_out / "multiseed_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    _write_rows_csv(base_out / "multiseed_metrics.csv", rows)
    _write_summary_csv(base_out / "multiseed_summary.csv", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
