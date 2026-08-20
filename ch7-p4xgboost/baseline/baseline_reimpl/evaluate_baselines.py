#!/usr/bin/env python3
"""
evaluate_baselines.py -- scores Jaqen-lite, POSEIDON-lite, and FlowLens-lite
against a labelled CIC-DDoS2019 flow CSV, restricted to the functional
metrics agreed in Stage 2 / Option A (accuracy, precision, recall, F1,
FPR/FNR, and data-plane memory footprint). Throughput/latency are
deliberately NOT computed here -- see README.md for why.

Usage:
    python3 evaluate_baselines.py --data your_flows.csv \
        --out ../results/table_7_6_functional.md

    # or, to sanity-check the pipeline with synthetic data:
    python3 smoke_test.py
"""
import argparse
import json
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

import jaqen_lite
import poseidon_lite
import flowlens_lite
from common import temporal_split


def compute_metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    acc = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    return {
        "accuracy": acc, "precision": precision, "recall": recall,
        "f1": f1, "fpr": fpr, "fnr": fnr, "tp": int(tp), "tn": int(tn),
        "fp": int(fp), "fn": int(fn),
    }


def _per_type_breakdown(test_df: pd.DataFrame, y_pred: np.ndarray) -> dict:
    """Real per-attack-type metrics (Table 7.4 style): for each real type
    present, score it against the benign rows in the same test set. Only
    computed when the flow CSV actually carries an attack_type column
    (older/synthetic inputs without it just skip this)."""
    if "attack_type" not in test_df.columns:
        return {}
    out = {}
    y_pred = np.asarray(y_pred)
    for atype in ["udp", "syn"]:
        mask = test_df["attack_type"].isin(["benign", atype]).to_numpy()
        if mask.sum() == 0 or (test_df["attack_type"].to_numpy()[mask] == atype).sum() == 0:
            out[atype] = {"note": f"no real {atype} rows in this test split"}
            continue
        out[atype] = compute_metrics(test_df["label"].to_numpy()[mask], y_pred[mask])
    return out


def evaluate(df: pd.DataFrame, ts_col: str) -> tuple[pd.DataFrame, dict]:
    rows = []
    per_type_all = {}

    # --- Jaqen-lite (threshold-based, no training; score on the same
    #     held-out test split as everyone else for a fair comparison) ---
    _, test_df = temporal_split(df, ts_col=ts_col)
    y_true = test_df["label"].to_numpy()
    y_pred = jaqen_lite.predict(test_df)
    m = compute_metrics(y_true, y_pred)
    m["system"] = "Jaqen-lite"
    m["memory_bytes"] = jaqen_lite.memory_footprint().bytes_total
    rows.append(m)
    per_type_all["Jaqen-lite"] = _per_type_breakdown(test_df, y_pred)

    # --- POSEIDON-lite (threshold-based) ---
    y_pred = poseidon_lite.predict(test_df)
    m = compute_metrics(y_true, y_pred)
    m["system"] = "POSEIDON-lite"
    m["memory_bytes"] = poseidon_lite.memory_footprint().bytes_total
    rows.append(m)
    per_type_all["POSEIDON-lite"] = _per_type_breakdown(test_df, y_pred)

    # --- FlowLens-lite (trained classifier) ---
    y_true_fl, y_pred_fl, _ = flowlens_lite.fit_predict(df, ts_col=ts_col)
    m = compute_metrics(y_true_fl, y_pred_fl)
    m["system"] = "FlowLens-lite"
    m["memory_bytes"] = flowlens_lite.memory_footprint().bytes_total
    rows.append(m)
    # FlowLens-lite does its own internal temporal_split (fit_predict), so
    # its test rows aren't necessarily the same `test_df` used above --
    # recompute the matching slice for a correct per-type breakdown.
    _, flowlens_test_df = temporal_split(df, ts_col=ts_col)
    per_type_all["FlowLens-lite"] = _per_type_breakdown(flowlens_test_df, y_pred_fl)

    cols = ["system", "accuracy", "precision", "recall", "f1", "fpr", "fnr", "memory_bytes"]
    return pd.DataFrame(rows)[cols], per_type_all


def to_markdown_table(results: pd.DataFrame, per_type_all: dict, p4xgboost_row: dict | None = None) -> str:
    lines = [
        "# Table 7.6 (functional-metrics-only replacement)",
        "",
        "**Scope:** functional re-creations of each baseline's core mechanism,",
        "scored on [DATASET] using the same temporal 80/20 split as P4-XGBoost.",
        "Throughput and latency are intentionally excluded -- see README.md.",
        "",
        "| System | Accuracy | Precision | Recall | F1 | FPR | FNR | Memory (bytes) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    rows = results.to_dict("records")
    if p4xgboost_row:
        rows.append(p4xgboost_row)
    for r in rows:
        lines.append(
            f"| {r['system']} | {r['accuracy']:.3f} | {r['precision']:.3f} | "
            f"{r['recall']:.3f} | {r['f1']:.3f} | {r['fpr']:.3f} | {r['fnr']:.3f} | "
            f"{int(r['memory_bytes']):,} |"
        )
    lines.append("")
    lines.append(
        "*Replace `[DATASET]` above with the actual CIC-DDoS2019 subset/date "
        "used, and cite this table's provenance (functional re-creation, "
        "not authors' code) directly beneath it in the thesis, per README.md.*"
    )

    if per_type_all:
        lines.append("")
        lines.append("## Per-attack-type breakdown (real, matching Table 7.4's structure)")
        lines.append("")
        lines.append("| System | Type | Accuracy | Precision | Recall | F1 | FPR |")
        lines.append("|---|---|---|---|---|---|---|")
        for system, types in per_type_all.items():
            for atype, m in types.items():
                if "note" in m:
                    lines.append(f"| {system} | {atype} | &mdash; | &mdash; | &mdash; | &mdash; | {m['note']} |")
                else:
                    lines.append(
                        f"| {system} | {atype} | {m['accuracy']:.3f} | {m['precision']:.3f} | "
                        f"{m['recall']:.3f} | {m['f1']:.3f} | {m['fpr']:.3f} |"
                    )
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="labelled flow CSV, see README.md for schema")
    ap.add_argument("--out", default="../results/table_7_6_functional.md")
    ap.add_argument("--ts-col", default="timestamp")
    ap.add_argument(
        "--p4xgboost-f1", type=float, default=None,
        help="P4-XGBoost's own real measured F1 to include as a reference row.",
    )
    ap.add_argument("--p4xgboost-accuracy", type=float, default=None)
    ap.add_argument("--p4xgboost-precision", type=float, default=None)
    ap.add_argument("--p4xgboost-recall", type=float, default=None)
    ap.add_argument("--p4xgboost-fpr", type=float, default=None)
    ap.add_argument("--p4xgboost-memory-bytes", type=int, default=None)
    args = ap.parse_args()

    df = pd.read_csv(args.data)
    required = {"protocol", "syn_count", "ack_count", "label", args.ts_col}
    missing = required - set(df.columns)
    if missing:
        print(f"ERROR: input CSV is missing required columns: {missing}", file=sys.stderr)
        sys.exit(1)

    results, per_type_all = evaluate(df, ts_col=args.ts_col)
    print(results.to_string(index=False))
    print(json.dumps(per_type_all, indent=2))

    p4xgboost_row = None
    if args.p4xgboost_f1 is not None:
        # Every field here must come from an explicit CLI flag backed by a
        # real measurement -- no hardcoded fallback values. A prior version
        # of this script hardcoded accuracy/precision/recall/fpr to the
        # thesis's original (fabricated) Table 7.4 numbers regardless of
        # what was actually measured; fixed here so every number in this
        # row traces to a real computation, same as the rest of the table.
        missing_fields = [
            name for name, val in [
                ("--p4xgboost-accuracy", args.p4xgboost_accuracy),
                ("--p4xgboost-precision", args.p4xgboost_precision),
                ("--p4xgboost-recall", args.p4xgboost_recall),
                ("--p4xgboost-fpr", args.p4xgboost_fpr),
                ("--p4xgboost-memory-bytes", args.p4xgboost_memory_bytes),
            ] if val is None
        ]
        if missing_fields:
            print(f"ERROR: --p4xgboost-f1 given but missing real values for: {missing_fields}. "
                  f"Supply all of them (real measurements) or omit --p4xgboost-f1 entirely.",
                  file=sys.stderr)
            sys.exit(1)
        p4xgboost_row = {
            "system": "P4-XGBoost (Ch7, real measured -- see evaluation_output/summary.json)",
            "accuracy": args.p4xgboost_accuracy, "precision": args.p4xgboost_precision,
            "recall": args.p4xgboost_recall,
            "f1": args.p4xgboost_f1, "fpr": args.p4xgboost_fpr, "fnr": float("nan"),
            "memory_bytes": args.p4xgboost_memory_bytes,
        }

    md = to_markdown_table(results, per_type_all, p4xgboost_row)
    with open(args.out, "w") as f:
        f.write(md)
    print(f"\nWrote {args.out}")

    json_out = args.out.rsplit(".", 1)[0] + "_per_type.json"
    with open(json_out, "w") as f:
        json.dump(per_type_all, f, indent=2)
    print(f"Wrote {json_out}")


if __name__ == "__main__":
    main()
