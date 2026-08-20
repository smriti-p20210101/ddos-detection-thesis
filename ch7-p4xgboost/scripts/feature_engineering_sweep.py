#!/usr/bin/env python3
"""Real feature-engineering test at the CURRENT 0.5s window (no window-size
increase, so no real detection-latency cost): adds syn_noack_ratio and
ack_ratio as explicit model features, computed from the same raw packet
cache window_sweep.py already built (ts, src_ip, proto, dst_port, size,
syn, ack -- no new tshark run needed).

syn_noack_ratio is the fraction of a window's packets that are
SYN-without-ACK -- already computed for ATTACK-TYPE LABELING in
train_model.py (as syn_only_count) but never exposed to the model as an
input feature. The existing tcp_flags feature is just SYN fraction, which
conflates real handshake SYNs with attack SYNs; syn_noack_ratio isolates
the attack-specific pattern directly.

Both P4-feasible: both are running per-packet counters over the SAME 0.5s
window the switch already accumulates other counters over -- no new
per-packet state beyond what's already tracked (syn, ack flags).
"""
import json
import os
import sys
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import (  # noqa: E402
    ATTACKER_IP, WINDOW_SECONDS, load_ml_hyperparams, per_type_temporal_split, _select_files,
)

RAW_CACHE_DIR = os.path.join(REPO_ROOT, "evaluation_output", "raw_packet_cache")
BASE_FEATURES = ["pkt_rate", "byte_rate", "duration", "proto_var", "port_div", "size_var", "tcp_flags", "inter_arrival"]
NEW_FEATURES = ["syn_noack_ratio", "ack_ratio"]
ALL_FEATURES = BASE_FEATURES + NEW_FEATURES


def aggregate_with_new_features(df: pd.DataFrame, window_seconds: float) -> pd.DataFrame:
    grouped = df.groupby(["src_ip", "window"])

    def agg_one(g: pd.DataFrame) -> pd.Series:
        count = len(g)
        ts_sorted = g["ts"].sort_values().to_numpy()
        span = ts_sorted[-1] - ts_sorted[0]
        duration = span if span > 0 else window_seconds
        pkt_rate = count / window_seconds
        byte_rate = g["size"].sum() / window_seconds
        proto_var = g["proto"].var(ddof=0) if count > 1 else 0.0
        port_div = float(g["dst_port"].nunique())
        size_var = g["size"].var(ddof=0) if count > 1 else 0.0
        tcp_flags = g["syn"].sum() / count
        inter_arrival = np.diff(ts_sorted).mean() if count > 1 else 0.0

        udp_count = int((g["proto"] == 17).sum())
        syn_noack_count = int(((g["proto"] == 6) & (g["syn"] == 1) & (g["ack"] == 0)).sum())
        syn_noack_ratio = syn_noack_count / count
        ack_ratio = g["ack"].sum() / count

        return pd.Series({
            "pkt_rate": pkt_rate, "byte_rate": byte_rate, "duration": duration,
            "proto_var": 0.0 if pd.isna(proto_var) else proto_var, "port_div": port_div,
            "size_var": 0.0 if pd.isna(size_var) else size_var,
            "tcp_flags": tcp_flags, "inter_arrival": inter_arrival,
            "syn_noack_ratio": syn_noack_ratio, "ack_ratio": ack_ratio,
            "udp_count": udp_count, "syn_only_count": syn_noack_count,
        })

    result = grouped.apply(agg_one, include_groups=False).reset_index()

    def attack_type(row):
        if row["src_ip"] != ATTACKER_IP:
            return "benign"
        if row["syn_only_count"] > row["udp_count"] and row["syn_only_count"] > 0:
            return "syn"
        return "udp"

    result["attack_type"] = result.apply(attack_type, axis=1)
    result["label"] = (result["attack_type"] != "benign").astype(int)
    return result.drop(columns=["udp_count", "syn_only_count"])


def build_dataset(window_seconds: float) -> pd.DataFrame:
    targets = _select_files()
    all_rows = []
    t0 = time.time()
    for fname, _, _ in targets:
        raw = pd.read_csv(os.path.join(RAW_CACHE_DIR, f"{fname}.csv"))
        raw["window"] = (raw["ts"] // window_seconds).astype(np.int64)
        all_rows.append(aggregate_with_new_features(raw, window_seconds))
    df = pd.concat(all_rows, ignore_index=True)
    print(f"[feature_eng] aggregated {len(df)} window-rows in {time.time() - t0:.1f}s")
    return df


def train_and_score(df: pd.DataFrame, feature_cols: list, label: str, param_overrides: dict = None) -> dict:
    params = load_ml_hyperparams()
    if param_overrides:
        params = dict(params, **param_overrides)
    train_df, test_df = per_type_temporal_split(df)
    X_train, y_train = train_df[feature_cols], train_df["label"]
    X_test, y_test = test_df[feature_cols], test_df["label"]

    model = xgb.XGBClassifier(
        n_estimators=params["n_estimators"], max_depth=params["max_depth"],
        learning_rate=params["learning_rate"], objective=params["objective"],
        eval_metric="logloss",
    )
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
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

    print(f"\n=== {label} ({len(feature_cols)} features: {feature_cols}) ===")
    print(f"confusion matrix:\n{cm}")
    print(f"accuracy={overall['accuracy']:.4f}  attack: precision={overall['attack']['precision']:.3f} "
          f"recall={overall['attack']['recall']:.3f} f1={overall['attack']['f1-score']:.3f}  "
          f"weighted_f1={overall['weighted avg']['f1-score']:.3f}")
    for atype, rep in per_type.items():
        print(f"  {atype}-vs-benign: precision={rep['attack']['precision']:.3f} "
              f"recall={rep['attack']['recall']:.3f} f1={rep['attack']['f1-score']:.3f}")

    return {
        "label": label, "features": feature_cols, "accuracy": overall["accuracy"],
        "attack_f1": overall["attack"]["f1-score"], "weighted_f1": overall["weighted avg"]["f1-score"],
        "per_attack_type": {k: {"precision": v["attack"]["precision"], "recall": v["attack"]["recall"],
                                 "f1": v["attack"]["f1-score"]} for k, v in per_type.items()},
    }


def main():
    df = build_dataset(WINDOW_SECONDS)
    print(f"[feature_eng] attack_type distribution:\n{df['attack_type'].value_counts()}")

    results = []
    results.append(train_and_score(df, BASE_FEATURES, "A: baseline 8 features (0.5s window)"))
    results.append(train_and_score(df, ALL_FEATURES, "B: baseline 8 + syn_noack_ratio + ack_ratio (0.5s window)"))
    results.append(train_and_score(
        df, ALL_FEATURES, "C: B's 10 features + tuned depth=9 (real CV-search best from earlier)",
        param_overrides={"max_depth": 9, "learning_rate": 0.2, "n_estimators": 100},
    ))

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "feature_engineering_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[feature_eng] wrote {out_path}")


if __name__ == "__main__":
    main()
