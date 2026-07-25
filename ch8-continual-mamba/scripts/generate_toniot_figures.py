from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"
FIGURES = ROOT / "paper" / "figures"


COLORS = {
    "p1": "#3b6fb6",
    "p2": "#2f9c67",
    "ak": "#8a5cc2",
    "bwt": "#c45a4a",
    "grid": "#d9d9d9",
}


def short_name(run: str) -> str:
    return (
        run.replace("ToN-IoT / Mamba+KAN ", "")
        .replace("No-EWC", "No EWC")
        .replace("EWC(", "EWC ")
        .replace(")", "")
    )


def save(fig: plt.Figure, name: str) -> None:
    FIGURES.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(FIGURES / name, dpi=300, bbox_inches="tight")
    plt.close(fig)


def style_axis(ax: plt.Axes, ylabel: str, ylim: tuple[float, float] | None = None) -> None:
    ax.set_ylabel(ylabel)
    if ylim is not None:
        ax.set_ylim(*ylim)
    ax.grid(axis="y", color=COLORS["grid"], linewidth=0.8, alpha=0.8)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def add_bar_labels(ax: plt.Axes, bars, fmt: str = "{:.1f}") -> None:
    for bar in bars:
        height = bar.get_height()
        va = "bottom" if height >= 0 else "top"
        offset = 1.0 if height >= 0 else -1.0
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + offset,
            fmt.format(height),
            ha="center",
            va=va,
            fontsize=8,
        )


def plot_toniot_retention_adaptation(df: pd.DataFrame) -> None:
    labels = [short_name(x) for x in df["Run"]]
    x = np.arange(len(labels))
    width = 0.24

    fig, ax = plt.subplots(figsize=(7.2, 4.1))
    b1 = ax.bar(x - width, df["Phase1After"], width, label="Phase-1 after", color=COLORS["p1"])
    b2 = ax.bar(x, df["Phase2After"], width, label="Phase-2 after", color=COLORS["p2"])
    b3 = ax.bar(x + width, df["Ak"], width, label="$A_k$", color=COLORS["ak"])
    add_bar_labels(ax, b1)
    add_bar_labels(ax, b2)
    add_bar_labels(ax, b3)
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    style_axis(ax, "Accuracy (%)", (0, 110))
    ax.legend(loc="upper center", ncol=3, frameon=False)
    ax.set_title("ToN-IoT Retention and Adaptation")
    save(fig, "toniot_retention_adaptation.png")


def plot_toniot_bwt(df: pd.DataFrame) -> None:
    labels = [short_name(x) for x in df["Run"]]
    fig, ax = plt.subplots(figsize=(6.8, 3.8))
    bars = ax.bar(labels, df["BWT"], color=COLORS["bwt"])
    add_bar_labels(ax, bars)
    ax.axhline(0, color="#333333", linewidth=1.0)
    style_axis(ax, "BWT (%)", (-40, 5))
    ax.set_title("ToN-IoT Backward Transfer")
    save(fig, "toniot_bwt.png")


def plot_toniot_ewc_sweep(df: pd.DataFrame) -> None:
    lambdas = [0.0, 0.2, 1.0, 5.0]
    fig, ax = plt.subplots(figsize=(6.8, 4.0))
    ax.plot(lambdas, df["Phase1After"], marker="o", label="Phase-1 after", color=COLORS["p1"])
    ax.plot(lambdas, df["Phase2After"], marker="o", label="Phase-2 after", color=COLORS["p2"])
    ax.plot(lambdas, df["Ak"], marker="o", label="$A_k$", color=COLORS["ak"])
    ax.set_xticks(lambdas)
    ax.set_xlabel("EWC $\\lambda$")
    style_axis(ax, "Score (%)", (55, 100))
    ax.legend(frameon=False)
    ax.set_title("ToN-IoT EWC Sensitivity")
    save(fig, "toniot_ewc_sweep.png")


def plot_cross_dataset_validation(cic: pd.DataFrame, toniot: pd.DataFrame) -> None:
    cic_main = cic[cic["Run"].isin(["Mamba+KAN / No-EWC", "Mamba+KAN / EWC(5)"])].copy()
    toniot_main = toniot[
        toniot["Run"].isin(["ToN-IoT / Mamba+KAN No-EWC", "ToN-IoT / Mamba+KAN EWC(0.2)"])
    ].copy()

    datasets = ["CIC-IoT2023", "ToN-IoT"]
    no_ewc = [
        float(cic_main.loc[cic_main["Run"] == "Mamba+KAN / No-EWC", "Ak"].iloc[0]),
        float(toniot_main.loc[toniot_main["Run"] == "ToN-IoT / Mamba+KAN No-EWC", "Ak"].iloc[0]),
    ]
    best_ewc = [
        float(cic_main.loc[cic_main["Run"] == "Mamba+KAN / EWC(5)", "Ak"].iloc[0]),
        float(toniot_main.loc[toniot_main["Run"] == "ToN-IoT / Mamba+KAN EWC(0.2)", "Ak"].iloc[0]),
    ]

    x = np.arange(len(datasets))
    width = 0.32
    fig, ax = plt.subplots(figsize=(5.8, 3.8))
    b1 = ax.bar(x - width / 2, no_ewc, width, label="No EWC", color="#6c757d")
    b2 = ax.bar(x + width / 2, best_ewc, width, label="Best EWC", color=COLORS["ak"])
    add_bar_labels(ax, b1)
    add_bar_labels(ax, b2)
    ax.set_xticks(x)
    ax.set_xticklabels(datasets)
    style_axis(ax, "$A_k$ (%)", (70, 85))
    ax.legend(frameon=False)
    ax.set_title("Cross-Dataset Continual Validation")
    save(fig, "cross_dataset_validation.png")


def main() -> None:
    toniot = pd.read_csv(OUTPUTS / "toniot_summary.csv")
    cic = pd.read_csv(OUTPUTS / "benchmark_summary.csv")
    plot_toniot_retention_adaptation(toniot)
    plot_toniot_bwt(toniot)
    plot_toniot_ewc_sweep(toniot)
    plot_cross_dataset_validation(cic, toniot)
    print(f"Wrote ToN-IoT paper figures to {FIGURES}")


if __name__ == "__main__":
    main()
