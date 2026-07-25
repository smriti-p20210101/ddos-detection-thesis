from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
OUTPUTS = ROOT / "outputs"


PAIRINGS = [
    ("Mamba+KAN / No-EWC", "Mamba+KAN / EWC(5)"),
    ("Mamba+MLP / No-EWC", "Mamba+MLP / EWC(5)"),
    ("MLP+KAN / No-EWC", "MLP+KAN / EWC(5)"),
]


def _pct(value: float) -> float:
    return float(value)


def analyze_summary(summary_path: Path) -> list[dict[str, float | str]]:
    df = pd.read_csv(summary_path)
    rows = []
    for no_ewc, ewc in PAIRINGS:
        base = df.loc[df["Run"] == no_ewc]
        regularized = df.loc[df["Run"] == ewc]
        if base.empty or regularized.empty:
            continue
        base_row = base.iloc[0]
        ewc_row = regularized.iloc[0]
        rows.append(
            {
                "Pair": ewc.replace(" / EWC(5)", ""),
                "Delta_P1_After": _pct(ewc_row["Phase1After"] - base_row["Phase1After"]),
                "Delta_P2_After": _pct(ewc_row["Phase2After"] - base_row["Phase2After"]),
                "Delta_BWT": _pct(ewc_row["BWT"] - base_row["BWT"]),
                "Delta_Ak": _pct(ewc_row["Ak"] - base_row["Ak"]),
                "Delta_P1_MacroF1": _pct(ewc_row["P1MacroF1"] - base_row["P1MacroF1"]),
                "Delta_P2_MacroF1": _pct(ewc_row["P2MacroF1"] - base_row["P2MacroF1"]),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, float | str]]) -> None:
    if not rows:
        return
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def write_markdown(path: Path, rows: list[dict[str, float | str]]) -> None:
    lines = [
        "# EWC Degradation Analysis",
        "",
        "Positive deltas mean EWC improved over the no-EWC counterpart. Negative deltas mean EWC hurt.",
        "",
        "| Pair | Delta P1 After | Delta P2 After | Delta BWT | Delta Ak | Delta P1 Macro-F1 | Delta P2 Macro-F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {Pair} | {Delta_P1_After:.2f} | {Delta_P2_After:.2f} | {Delta_BWT:.2f} | "
            "{Delta_Ak:.2f} | {Delta_P1_MacroF1:.2f} | {Delta_P2_MacroF1:.2f} |".format(**row)
        )
    lines.extend(
        [
            "",
            "Interpretation cue: if Delta BWT and Delta Ak disagree, EWC may be trading retention against adaptation.",
            "The MLP+KAN pair is the main degradation case: EWC sharply lowers old-task retention and average accuracy despite high Phase-2 accuracy.",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze EWC effects in benchmark_summary.csv")
    parser.add_argument("--summary", type=str, default=str(OUTPUTS / "benchmark_summary.csv"))
    parser.add_argument("--output-dir", type=str, default=str(OUTPUTS / "analysis"))
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = analyze_summary(Path(args.summary))
    write_csv(out_dir / "ewc_pairwise_deltas.csv", rows)
    write_markdown(out_dir / "ewc_pairwise_deltas.md", rows)
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()
