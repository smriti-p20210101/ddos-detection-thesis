from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EVALUATION_DIR = PROJECT_ROOT / "evaluation"
OUTPUT_DIR = PROJECT_ROOT / "evaluation_output"
LOG_DIR = PROJECT_ROOT / "logs"
SUMMARY_PATH = OUTPUT_DIR / "summary.json"
REPORT_LOG_PATH = LOG_DIR / "p4xgboost_replication.log"


def ensure_directories() -> None:
    """Create the on-disk folders used by the replication pipeline."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
