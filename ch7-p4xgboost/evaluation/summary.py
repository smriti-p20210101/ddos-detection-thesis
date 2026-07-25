from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .ablation import build_ablation_manifest
from .data import ATTACK_METRICS, ABLATION_STUDIES, CONFUSION_MATRIX, LATENCY_BREAKDOWN
from .paths import SUMMARY_PATH


def write_summary_json(generated_files: list[str]) -> Path:
    payload = {
        "paper": "P4-XGBoost: High-Speed Hybrid DDoS Defense",
        "confusion_matrix": asdict(CONFUSION_MATRIX),
        "attack_metrics": [asdict(row) for row in ATTACK_METRICS],
        "latency_breakdown": [asdict(row) for row in LATENCY_BREAKDOWN],
        "ablations": build_ablation_manifest(),
        "generated_files": generated_files,
        "expected_results": {
            "f1_score": 0.974,
            "latency_ms": 28.0,
            "auc": 0.986,
        },
    }
    SUMMARY_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[Generated] {SUMMARY_PATH}")
    return SUMMARY_PATH
