from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"
FIGURES = ROOT / "paper" / "figures"


COLORS = {
    "er": "#3b6fb6",
    "derpp": "#2f9c67",
    "ak": "#8a5cc2",
    "bwt": "#c45a4a",
    "forget": "#d08b3e",
    "grid": "#d9d9d9",
}


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save(fig: plt.Figure, name: str) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIGURES / name, dpi=300, bbox_inches="tight")
    plt.close(fig)


def short_task(name: str) -> str:
    return (
        name.replace("task1_", "T1 ")
        .replace("task2_", "T2 ")
        .replace("task3_", "T3 ")
        .replace("task4_", "T4 ")
        .replace("_", " ")
        .title()
    )


def style_axis(ax: plt.Axes, ylabel: str) -> None:
    ax.set_ylabel(ylabel)
    ax.grid(axis="y", color=COLORS["grid"], linewidth=0.8, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def plot_accuracy_matrix(metrics: dict) -> None:
    task_names = [short_task(x) for x in metrics["task_names"]]
    matrix_rows = metrics["accuracy_matrix"]
    n = len(task_names)
    mat = np.full((n, n), np.nan)
    for row_idx, row in enumerate(matrix_rows):
        for col_idx, value in enumerate(row):
            mat[row_idx, col_idx] = float(value) * 100.0

    fig, ax = plt.subplots(figsize=(6.2, 4.8))
    masked = np.ma.masked_invalid(mat)
    im = ax.imshow(masked, cmap="YlGnBu", vmin=0, vmax=100)
    ax.set_xticks(np.arange(n))
    ax.set_yticks(np.arange(n))
    ax.set_xticklabels(task_names, rotation=30, ha="right")
    ax.set_yticklabels([f"After T{i + 1}" for i in range(n)])
    ax.set_title("4-Task Smoke Accuracy Matrix (ER+EWC)")
    for i in range(n):
        for j in range(n):
            if not np.isnan(mat[i, j]):
                ax.text(j, i, f"{mat[i, j]:.1f}", ha="center", va="center", fontsize=8)
    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Accuracy (%)")
    save(fig, "multitask_smoke_accuracy_matrix.png")


def plot_final_task_comparison(er: dict, derpp: dict, erace: dict | None, joint: dict | None) -> None:
    task_names = [short_task(x) for x in er["task_names"]]
    series = [
        ("ER+EWC", [er[f"{name}_test_acc_after_final"] * 100.0 for name in er["task_names"]], COLORS["er"]),
        ("DER++ + EWC", [derpp[f"{name}_test_acc_after_final"] * 100.0 for name in derpp["task_names"]], COLORS["derpp"]),
    ]
    if erace is not None:
        series.append(
            (
                "ER-ACE+EWC",
                [erace[f"{name}_test_acc_after_final"] * 100.0 for name in erace["task_names"]],
                "#6c757d",
            )
        )
    if joint is not None:
        series.append(
            (
                "Joint upper",
                [joint[f"{name}_test_acc_after_final"] * 100.0 for name in joint["task_names"]],
                "#d08b3e",
            )
        )
    x = np.arange(len(task_names))
    width = min(0.8 / len(series), 0.28)

    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    offsets = np.linspace(-width * (len(series) - 1) / 2, width * (len(series) - 1) / 2, len(series))
    for offset, (label, values, color) in zip(offsets, series):
        bars = ax.bar(x + offset, values, width, label=label, color=color)
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 1.0,
                f"{bar.get_height():.1f}",
                ha="center",
                va="bottom",
                fontsize=8,
            )
    ax.set_xticks(x)
    ax.set_xticklabels(task_names, rotation=25, ha="right")
    ax.set_ylim(0, 110)
    style_axis(ax, "Final Accuracy (%)")
    ax.legend(frameon=False)
    ax.set_title("4-Task Smoke Final Accuracy")
    save(fig, "multitask_smoke_final_accuracy.png")


def plot_multiseed_summary(summary: dict) -> None:
    metrics = [
        ("Avg. Acc.", "average_accuracy_ak", COLORS["ak"], 100.0),
        ("Avg. Macro-F1", "average_macro_f1_final", COLORS["er"], 100.0),
        ("BWT", "bwt", COLORS["bwt"], 100.0),
        ("Forgetting", "average_forgetting", COLORS["forget"], 100.0),
    ]
    labels = [m[0] for m in metrics]
    means = [summary[m[1]]["mean"] * m[3] for m in metrics]
    stds = [summary[m[1]]["std"] * m[3] for m in metrics]

    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    bars = ax.bar(labels, means, yerr=stds, capsize=4, color=[m[2] for m in metrics])
    for bar in bars:
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 1.0,
            f"{bar.get_height():.1f}",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    ax.axhline(0, color="#333333", linewidth=1.0)
    style_axis(ax, "Score (%)")
    ax.set_title("4-Task Smoke Multi-Seed Summary (n=2)")
    save(fig, "multiseed_smoke_summary.png")


def main() -> None:
    er = load_json(OUTPUTS / "smoke_4task_er" / "latest_metrics.json")
    derpp = load_json(OUTPUTS / "smoke_4task_derpp" / "latest_metrics.json")
    summary = load_json(OUTPUTS / "smoke_4task_er_multiseed" / "multiseed_summary.json")
    erace_path = OUTPUTS / "smoke_4task_erace" / "seed_42" / "latest_metrics.json"
    joint_path = OUTPUTS / "smoke_4task_joint_upper" / "latest_metrics.json"
    erace = load_json(erace_path) if erace_path.exists() else None
    joint = load_json(joint_path) if joint_path.exists() else None
    plot_accuracy_matrix(er)
    plot_final_task_comparison(er, derpp, erace, joint)
    plot_multiseed_summary(summary)
    print(f"Wrote multi-task smoke figures to {FIGURES}")


if __name__ == "__main__":
    main()
