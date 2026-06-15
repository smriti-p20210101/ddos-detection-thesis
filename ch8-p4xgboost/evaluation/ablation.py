from __future__ import annotations

from dataclasses import asdict
from typing import Any

from .data import ABLATION_STUDIES


def build_ablation_manifest() -> list[dict[str, Any]]:
    return [
        {
            "title": study.title,
            "headers": list(study.headers),
            "starred_label": study.starred_label,
            "rows": [asdict(row) for row in study.rows],
        }
        for study in ABLATION_STUDIES
    ]


def build_ablation_summary_text() -> str:
    lines: list[str] = []
    for study in ABLATION_STUDIES:
        lines.append(study.title)
        lines.append("-" * len(study.title))
        lines.append(f"Baseline: {study.starred_label}")
        for row in study.rows:
            if row.third_metric:
                lines.append(f"{row.label} -> {row.f1_score} / {row.second_metric} / {row.third_metric}")
            else:
                lines.append(f"{row.label} -> {row.f1_score} / {row.second_metric}")
        lines.append("")
    return "\n".join(lines).rstrip()
