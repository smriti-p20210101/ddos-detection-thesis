#!/usr/bin/env python3
"""Real threshold retuning for Jaqen-lite and POSEIDON-lite at the fixed
0.5s window (see all_baselines_windowed.py): their real thresholds
(SYN_THRESH=20, UDP_THRESH=50, ASYM_THRESH=15, SYN_ACK_ASYM_T=15,
DNS_RATE_LIMIT=100) were implicitly calibrated for real per-COMPLETE-FLOW
counts (median several seconds of accumulation), so applied unchanged to
0.5s-window counts they barely ever fire -- Jaqen-lite collapsed to
attack F1=0.001, POSEIDON-lite to 38% accuracy with a 59.8% FPR. Reporting
that as "the windowed result" without retuning would unfairly deflate
these baselines the same way it would be unfair to inflate P4-XGBoost by
cherry-picking a favorable window.

Grid search is done on the TRAINING split only (never touches the real
test set during search, same leakage-safe method used for the XGBoost
hyperparameter search in scripts/tune_model_search.py), scored by attack
F1, then the single best combo per system is applied once to the real
held-out test set.
"""
import itertools
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from controller.ml.train_model import WINDOW_SECONDS, per_type_temporal_split  # noqa: E402
from all_baselines_windowed import build_windowed_dataset  # noqa: E402

CACHE_PATH = os.path.join(REPO_ROOT, "evaluation_output", f"windowed_baseline_dataset_{WINDOW_SECONDS}s.csv")

# Real ranges: original real full-flow thresholds as the ceiling, swept
# down toward what a 0.5s window can plausibly accumulate.
JAQEN_GRID = {
    "syn_thresh": [1, 2, 3, 5, 8, 12, 20],
    "udp_thresh": [1, 2, 3, 5, 8, 12, 20, 30, 50],
    "asym_thresh": [0, 1, 2, 5, 10, 15],
}
POSEIDON_GRID = {
    "syn_ack_asym_t": [0, 1, 2, 5, 10, 15],
    "dns_rate_limit": [1, 2, 5, 10, 20, 50, 100],
}


def jaqen_predict(df, syn_thresh, udp_thresh, asym_thresh):
    syn = df["syn_count"].to_numpy()
    ack = df["ack_count"].to_numpy()
    is_udp = (df["protocol"].astype(str).str.upper() == "UDP").to_numpy()
    udp_count = df["udp_count"].to_numpy()
    syn_asym = (syn > syn_thresh) & ((syn - ack) > asym_thresh)
    udp_heavy = is_udp & (udp_count > udp_thresh)
    return (syn_asym | udp_heavy).astype(int)


def poseidon_predict(df, syn_ack_asym_t, dns_rate_limit):
    preds = np.zeros(len(df), dtype=int)
    is_tcp = (df["protocol"].astype(str).str.upper() == "TCP").to_numpy()
    syn = df["syn_count"].to_numpy()
    ack = df["ack_count"].to_numpy()
    asym = syn - ack
    drop_mask = is_tcp & (asym > syn_ack_asym_t)
    pass_mask = is_tcp & (syn == ack)
    gray_mask = is_tcp & ~drop_mask & ~pass_mask
    completes_handshake = df["pkt_count"].to_numpy() > (syn + ack)
    gray_attack = gray_mask & ~completes_handshake
    preds[drop_mask] = 1
    preds[gray_attack] = 1
    is_udp_dns = (df["protocol"].astype(str).str.upper() == "UDP") & (df["dst_port"] == 53)
    dns_unmatched = df["dns_query_matched"].to_numpy() == 0
    dns_over_rate = df["udp_count"].to_numpy() > dns_rate_limit
    preds[(is_udp_dns & (dns_unmatched | dns_over_rate)).to_numpy()] = 1
    return preds


def grid_search(name, predict_fn, grid, train_df):
    y_train = train_df["label"].to_numpy()
    keys = list(grid.keys())
    best = None
    for combo in itertools.product(*grid.values()):
        params = dict(zip(keys, combo))
        y_pred = predict_fn(train_df, **params)
        f1 = f1_score(y_train, y_pred, zero_division=0)
        if best is None or f1 > best[0]:
            best = (f1, params)
    print(f"[{name}] best train-only F1={best[0]:.4f} at {best[1]}")
    return best[1]


def evaluate(name, y_test, y_pred, test_df):
    cm = confusion_matrix(y_test, y_pred)
    overall = classification_report(y_test, y_pred, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)
    print(f"\n=== {name} (retuned, {WINDOW_SECONDS}s window) ===")
    print(f"confusion matrix:\n{cm}")
    print(f"accuracy={overall['accuracy']:.4f}  attack: precision={overall['attack']['precision']:.3f} "
          f"recall={overall['attack']['recall']:.3f} f1={overall['attack']['f1-score']:.3f}  "
          f"fpr={cm[0][1] / (cm[0][1] + cm[0][0]):.3f}")

    per_type = {}
    for atype in ["udp", "syn"]:
        mask = test_df["attack_type"].isin(["benign", atype])
        if (test_df.loc[mask, "attack_type"] == atype).sum() == 0:
            continue
        y_t = test_df.loc[mask, "label"]
        y_p = pd.Series(y_pred, index=test_df.index).loc[mask]
        rep = classification_report(y_t, y_p, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)
        per_type[atype] = {"precision": rep["attack"]["precision"], "recall": rep["attack"]["recall"],
                            "f1": rep["attack"]["f1-score"]}
        print(f"  {atype}-vs-benign: precision={rep['attack']['precision']:.3f} "
              f"recall={rep['attack']['recall']:.3f} f1={rep['attack']['f1-score']:.3f}")

    return {
        "system": name, "accuracy": overall["accuracy"], "attack_f1": overall["attack"]["f1-score"],
        "weighted_f1": overall["weighted avg"]["f1-score"], "fpr": cm[0][1] / (cm[0][1] + cm[0][0]),
        "per_attack_type": per_type,
    }


def main():
    if os.path.exists(CACHE_PATH):
        df = pd.read_csv(CACHE_PATH)
        print(f"[baselines_tuned] loaded cached windowed dataset ({len(df)} rows) from {CACHE_PATH}")
    else:
        df = build_windowed_dataset(WINDOW_SECONDS)

    train_df, test_df = per_type_temporal_split(df)
    y_test = test_df["label"].to_numpy()

    jaqen_best = grid_search("Jaqen-lite", jaqen_predict, JAQEN_GRID, train_df)
    y_pred = jaqen_predict(test_df, **jaqen_best)
    jaqen_result = evaluate("Jaqen-lite (retuned)", y_test, y_pred, test_df)
    jaqen_result["tuned_params"] = jaqen_best

    poseidon_best = grid_search("POSEIDON-lite", poseidon_predict, POSEIDON_GRID, train_df)
    y_pred = poseidon_predict(test_df, **poseidon_best)
    poseidon_result = evaluate("POSEIDON-lite (retuned)", y_test, y_pred, test_df)
    poseidon_result["tuned_params"] = poseidon_best

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "baselines_tuned_windowed.json")
    with open(out_path, "w") as f:
        json.dump([jaqen_result, poseidon_result], f, indent=2)
    print(f"\n[baselines_tuned] wrote {out_path}")


if __name__ == "__main__":
    main()
