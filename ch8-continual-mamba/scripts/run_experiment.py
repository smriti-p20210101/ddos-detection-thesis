from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from continual_mamba.config import ExperimentConfig  # noqa: E402
from continual_mamba.train import run_experiment  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Continual-Mamba experiment")
    parser.add_argument("--config", type=str, required=True, help="Path to config json")
    args = parser.parse_args()

    config = ExperimentConfig.load(args.config)
    metrics = run_experiment(config)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()

