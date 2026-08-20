#!/usr/bin/env python3
"""Real apples-to-apples re-evaluation of FlowLens-lite at a FIXED window
(same 0.5s cadence as P4-XGBoost), instead of its original per-complete-flow
operating point (baseline/baseline_reimpl/flowlens_lite.py, which needs an
entire flow's packets before classifying -- real measured median 3-5s per
attack flow, tail into the thousands of seconds; see the window-sweep
discussion).

This groups by (src_ip, 0.5s window) -- the SAME grouping train_model.py
uses -- and builds the SAME bin_i = pkt_len >> 4 histogram (QL=4, 10 bins,
truncated) that baseline_reimpl/common.py's ensure_bin_histogram already
uses, just computed per-window instead of per-flow. Trains the same
RandomForestClassifier (n_estimators=100, max_depth=None) FlowLens-lite
already uses, on the same real per-type temporal 80/20 split.

Real, not assumed: uses the raw_packet_cache/ built by window_sweep.py (ts,
src_ip, proto, dst_port, size, syn, ack per packet) -- no new tshark run.
"""
import json
import os
import sys
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import ATTACKER_IP, WINDOW_SECONDS, _select_files, per_type_temporal_split  # noqa: E402

RAW_CACHE_DIR = os.path.join(REPO_ROOT, "evaluation_output", "raw_packet_cache")
NUM_BINS = 10
QUANT_SHIFT = 4
BIN_COLS = [f"bin_{i}" for i in range(NUM_BINS)]


def build_windowed_histograms(window_seconds: float) -> pd.DataFrame:
    targets = _select_files()
    all_rows = []
    t0 = time.time()
    for fname, _, _ in targets:
        raw = pd.read_csv(os.path.join(RAW_CACHE_DIR, f"{fname}.csv"))
        raw["window"] = (raw["ts"] // window_seconds).astype(np.int64)
        raw["bin"] = (raw["size"].astype(np.int64) // (2 ** QUANT_SHIFT)).clip(upper=NUM_BINS)  # >=NUM_BINS truncated out

        grouped = raw.groupby(["src_ip", "window"])

        def agg_one(g: pd.DataFrame) -> pd.Series:
            hist = np.zeros(NUM_BINS, dtype=np.float64)
            counts = g["bin"].value_counts()
            for b, c in counts.items():
                if b < NUM_BINS:
                    hist[int(b)] = c
            udp_count = int((g["proto"] == 17).sum())
            syn_noack_count = int(((g["proto"] == 6) & (g["syn"] == 1) & (g["ack"] == 0)).sum())
            data = dict(zip(BIN_COLS, hist))
            data["udp_count"] = udp_count
            data["syn_only_count"] = syn_noack_count
            return pd.Series(data)

        result = grouped.apply(agg_one, include_groups=False).reset_index()

        def attack_type(row):
            if row["src_ip"] != ATTACKER_IP:
                return "benign"
            if row["syn_only_count"] > row["udp_count"] and row["syn_only_count"] > 0:
                return "syn"
            return "udp"

        result["attack_type"] = result.apply(attack_type, axis=1)
        result["label"] = (result["attack_type"] != "benign").astype(int)
        all_rows.append(result.drop(columns=["udp_count", "syn_only_count"]))

    df = pd.concat(all_rows, ignore_index=True)
    print(f"[flowlens_windowed] aggregated {len(df)} window-rows in {time.time() - t0:.1f}s")
    return df


def train_and_score(df: pd.DataFrame, window_seconds: float) -> dict:
    train_df, test_df = per_type_temporal_split(df)
    X_train, y_train = train_df[BIN_COLS].to_numpy(), train_df["label"].to_numpy()
    X_test, y_test = test_df[BIN_COLS].to_numpy(), test_df["label"].to_numpy()

    clf = RandomForestClassifier(n_estimators=100, max_depth=None, random_state=0, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    cm = confusion_matrix(y_test, y_pred)
    overall = classification_report(y_test, y_pred, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)

    per_type = {}
    for atype in ["udp", "syn"]:
        mask = test_df["attack_type"].isin(["benign", atype])
        if (test_df.loc[mask, "attack_type"] == atype).sum() == 0:
            continue
        y_t = test_df.loc[mask, "label"]
        y_p = pd.Series(y_pred, index=test_df.index).loc[mask]
        per_type[atype] = classification_report(y_t, y_p, target_names=["benign", "attack"],
                                                  digits=3, output_dict=True, zero_division=0)

    print(f"\n=== FlowLens-lite @ {window_seconds}s fixed window (real, apples-to-apples) ===")
    print(f"confusion matrix:\n{cm}")
    print(f"accuracy={overall['accuracy']:.4f}  attack: precision={overall['attack']['precision']:.3f} "
          f"recall={overall['attack']['recall']:.3f} f1={overall['attack']['f1-score']:.3f}  "
          f"weighted_f1={overall['weighted avg']['f1-score']:.3f}")
    for atype, rep in per_type.items():
        print(f"  {atype}-vs-benign: precision={rep['attack']['precision']:.3f} "
              f"recall={rep['attack']['recall']:.3f} f1={rep['attack']['f1-score']:.3f}")

    return {
        "window_seconds": window_seconds, "accuracy": overall["accuracy"],
        "attack_f1": overall["attack"]["f1-score"], "weighted_f1": overall["weighted avg"]["f1-score"],
        "confusion_matrix": cm.tolist(),
        "per_attack_type": {k: {"precision": v["attack"]["precision"], "recall": v["attack"]["recall"],
                                 "f1": v["attack"]["f1-score"]} for k, v in per_type.items()},
    }


def main():
    window_seconds = float(sys.argv[1]) if len(sys.argv) > 1 else WINDOW_SECONDS
    df = build_windowed_histograms(window_seconds)
    print(f"[flowlens_windowed] attack_type distribution:\n{df['attack_type'].value_counts()}")
    result = train_and_score(df, window_seconds)

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "flowlens_windowed_results.json")
    existing = []
    if os.path.exists(out_path):
        with open(out_path) as f:
            existing = json.load(f)
    existing = [r for r in existing if r["window_seconds"] != window_seconds] + [result]
    existing.sort(key=lambda r: r["window_seconds"])
    with open(out_path, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"[flowlens_windowed] wrote {out_path}")


if __name__ == "__main__":
    main()
