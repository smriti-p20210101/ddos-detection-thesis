from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .data import (
    ACCURACY_COMPARISON,
    FEATURE_IMPORTANCE,
    LATENCY_COMPARISON,
    ROC_GOSSIP_FPR,
    ROC_GOSSIP_TPR,
    ROC_OURS_FPR,
    ROC_OURS_TPR,
)
from .paths import OUTPUT_DIR


def _save_current_figure(filename: str) -> Path:
    path = OUTPUT_DIR / filename
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[Generated] {path}")
    return path


def generate_roc_curve() -> Path:
    plt.figure(figsize=(7, 5))
    plt.plot([0, 1], [0, 1], "k--", label="Random Guess")
    plt.plot(
        ROC_GOSSIP_FPR,
        ROC_GOSSIP_TPR,
        color="darkred",
        lw=2,
        label="Gossip Static Thresholds (AUC = 0.812)",
    )
    plt.plot(
        ROC_OURS_FPR,
        ROC_OURS_TPR,
        color="darkblue",
        lw=2,
        label="P4-XGBoost (AUC = 0.986)",
    )
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    return _save_current_figure("fig_4_roc_curve.png")


def generate_feature_importance() -> Path:
    labels = [label for label, _ in FEATURE_IMPORTANCE]
    values = [value for _, value in FEATURE_IMPORTANCE]
    plt.figure(figsize=(8, 5))
    plt.barh(labels, values, color="royalblue", edgecolor="darkblue")
    plt.xlabel("Feature Importance Score")
    plt.title("XGBoost Feature Importance Distribution")
    plt.grid(axis="x", alpha=0.3)
    return _save_current_figure("fig_5_feature_importance.png")


def generate_latency_comparison() -> Path:
    labels = [row.architecture for row in LATENCY_COMPARISON]
    values = [row.latency_ms for row in LATENCY_COMPARISON]
    plt.figure(figsize=(8, 5))
    bars = plt.bar(labels, values, color="lightcoral", edgecolor="darkred")
    bars[1].set_color("royalblue")
    bars[1].set_edgecolor("darkblue")
    plt.axhline(y=50, color="blue", linestyle="--", label="50ms Industry Target SLA")
    plt.ylabel("Latency (ms)")
    plt.title("Mitigation Latency Comparison")
    plt.xticks(rotation=30, ha="right")
    plt.legend()
    plt.grid(axis="y", alpha=0.3)
    return _save_current_figure("fig_6_latency_compare.png")


def generate_accuracy_comparison() -> Path:
    labels = [row.architecture for row in ACCURACY_COMPARISON]
    values = [row.f1_score for row in ACCURACY_COMPARISON]
    plt.figure(figsize=(8, 5))
    bars = plt.bar(labels, values, color="lightgray", edgecolor="gray")
    bars[5].set_color("royalblue")
    bars[5].set_edgecolor("darkblue")
    plt.ylabel("F1-Score")
    plt.title("Mitigation Accuracy Comparison (F1-Score)")
    plt.xticks(rotation=30, ha="right")
    plt.ylim(0, 1.1)
    plt.grid(axis="y", alpha=0.3)
    return _save_current_figure("fig_7_accuracy_compare.png")


def generate_all_figures() -> list[Path]:
    return [
        generate_roc_curve(),
        generate_feature_importance(),
        generate_latency_comparison(),
        generate_accuracy_comparison(),
    ]
