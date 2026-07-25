from __future__ import annotations

from io import StringIO
from typing import Iterable

from .data import ATTACK_METRICS, ABLATION_STUDIES, CONFUSION_MATRIX, LATENCY_BREAKDOWN


def _emit(lines: Iterable[str]) -> str:
    text = "\n".join(lines)
    print(text)
    return text


def render_confusion_matrix() -> str:
    lines = [
        "--- Table 2: System Confusion Matrix (Test Set: N=20,000) ---",
        f"{'':<15} {'Predicted Benign':<20} {'Predicted Attack':<20}",
        f"{'Actual Benign':<15} {'9,675 (True Negative)':<20} {'325 (False Positive)':<20}",
        f"{'Actual Attack':<15} {'195 (False Negative)':<20} {'9,805 (True Positive)':<20}",
    ]
    return _emit(lines)


def render_metrics_table() -> str:
    lines = ["--- Table 3: Detailed Performance Metrics by Attack Vector ---"]
    lines.append(
        f"{'Attack Typology':<22} | {'Precision':<10} | {'Recall':<10} | {'FPR (%)':<10} | {'F1-Score':<10}"
    )
    lines.append("-" * 75)
    for row in ATTACK_METRICS:
        lines.append(
            f"{row.attack_typology:<22} | {row.precision:<10.3f} | {row.recall:<10.3f} | "
            f"{row.false_positive_rate:<10} | {row.f1_score:<10.3f}"
        )
    return _emit(lines)


def render_latency_table() -> str:
    lines = ["--- Table 4: End-to-End Latency Breakdown ---"]
    for stage in LATENCY_BREAKDOWN:
        lines.append(f"{stage.stage:<55} | {stage.latency_ms:<10}")
    return _emit(lines)


def render_ablation_tables() -> str:
    buffer = StringIO()
    buffer.write("\n" + "=" * 70 + "\n")
    buffer.write("                 ABLATION STUDIES ANALYSIS\n")
    buffer.write("=" * 70 + "\n")

    for study in ABLATION_STUDIES:
        buffer.write(f"\n--- {study.title} ---\n")
        if study.title.endswith("Temporal Window Reset Interval (W)"):
            buffer.write(f"{study.headers[0]:<25} | {study.headers[1]:<10} | {study.headers[2]}\n")
            buffer.write("-" * 75 + "\n")
        elif len(study.headers) == 4 and study.headers[3]:
            buffer.write(
                f"{study.headers[0]:<25} | {study.headers[1]:<10} | {study.headers[2]:<10} | {study.headers[3]}\n"
            )
            buffer.write("-" * 75 + "\n")
        else:
            buffer.write(
                f"{study.headers[0]:<25} | {study.headers[1]:<10} | {study.headers[2]:<10} | {study.headers[3]:<10}\n"
            )
            buffer.write("-" * 65 + "\n")

        for row in study.rows:
            if study.title.endswith("Window Reset Interval (W)"):
                buffer.write(f"{row.label:<25} | {row.f1_score:<10} | {row.second_metric}\n")
            elif study.title.endswith("Bloom Deduplication Logic"):
                buffer.write(
                    f"{row.label:<25} | {row.f1_score:<15} | {row.second_metric:<15} | {row.third_metric}\n"
                )
            elif study.title.endswith("Threshold Parameter (T) Tuning"):
                buffer.write(
                    f"{row.label:<25} | {row.f1_score:<10} | {row.second_metric:<10} | {row.third_metric}\n"
                )
            elif study.title.endswith("Maximum Tree Depth"):
                buffer.write(
                    f"{row.label:<25} | {row.f1_score:<10} | {row.second_metric:<10} | {row.third_metric}\n"
                )
            elif study.title.endswith("Register Width)"):
                buffer.write(
                    f"{row.label:<25} | {row.f1_score:<10} | {row.second_metric:<10} | {row.third_metric}\n"
                )
            else:
                buffer.write(
                    f"{row.label:<25} | {row.f1_score:<10} | {row.second_metric:<10} | {row.third_metric:<10}\n"
                )

        if study.title.endswith("Window Reset Interval (W)"):
            buffer.write("\n* Denotes baseline configuration adopted in P4-XGBoost.\n")

    text = buffer.getvalue().rstrip()
    print(text)
    return text


def render_all_tables() -> str:
    sections = [
        render_confusion_matrix(),
        render_metrics_table(),
        render_latency_table(),
        render_ablation_tables(),
    ]
    return "\n\n".join(sections)
