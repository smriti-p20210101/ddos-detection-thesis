#!/usr/bin/env python3
"""Real apples-to-apples re-evaluation of ALL THREE baselines (Jaqen-lite,
POSEIDON-lite, FlowLens-lite) at the same fixed 0.5s window P4-XGBoost's
own feature extraction uses -- instead of their original per-complete-flow
operating point (baseline/baseline_reimpl/real_flows.csv, median ~3s for a
real UDP-attack flow, ~5s for a real SYN-attack flow, tail into the
thousands of seconds).

Jaqen-lite and POSEIDON-lite are threshold rules, not trained models, so
this reuses their REAL predict() functions unchanged (imported directly
from baseline_reimpl/) against real per-window syn/ack/udp counts instead
of per-flow counts -- no reimplementation of their logic, so no risk of
silently diverging from the real, already-reviewed rule definitions.
FlowLens-lite's windowed histogram logic is the same one already built and
run in scripts/flowlens_window_sweep.py.

Real, not assumed: built from the raw_packet_cache/ window_sweep.py
already populated (ts, src_ip, proto, dst_port, size, syn, ack per
packet) -- no new tshark run.
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
BASELINE_DIR = os.path.join(REPO_ROOT, "baseline", "baseline_reimpl")
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, BASELINE_DIR)

from controller.ml.train_model import ATTACKER_IP, WINDOW_SECONDS, _select_files, per_type_temporal_split  # noqa: E402
import jaqen_lite  # noqa: E402
import poseidon_lite  # noqa: E402

RAW_CACHE_DIR = os.path.join(REPO_ROOT, "evaluation_output", "raw_packet_cache")
NUM_BINS = 10
QUANT_SHIFT = 4
BIN_COLS = [f"bin_{i}" for i in range(NUM_BINS)]


def build_windowed_dataset(window_seconds: float) -> pd.DataFrame:
    """One combined per-(src_ip, window) table with everything all three
    baselines (and P4-XGBoost's own attack-type labeling) need."""
    targets = _select_files()
    all_rows = []
    t0 = time.time()
    for fname, _, _ in targets:
        raw = pd.read_csv(os.path.join(RAW_CACHE_DIR, f"{fname}.csv"))
        raw["window"] = (raw["ts"] // window_seconds).astype(np.int64)
        raw["bin"] = (raw["size"].astype(np.int64) // (2 ** QUANT_SHIFT)).clip(upper=NUM_BINS)
        raw["is_udp"] = raw["proto"] == 17
        raw["is_tcp"] = raw["proto"] == 6
        raw["is_dns_udp"] = raw["is_udp"] & (raw["dst_port"] == 53)

        grouped = raw.groupby(["src_ip", "window"])

        def agg_one(g: pd.DataFrame) -> pd.Series:
            pkt_count = len(g)
            syn_count = int(g["syn"].sum())
            ack_count = int(g["ack"].sum())
            udp_count = int(g["is_udp"].sum())
            tcp_count = int(g["is_tcp"].sum())
            dns_udp_count = int(g["is_dns_udp"].sum())
            syn_noack_count = int(((g["proto"] == 6) & (g["syn"] == 1) & (g["ack"] == 0)).sum())

            hist = np.zeros(NUM_BINS, dtype=np.float64)
            for b, c in g["bin"].value_counts().items():
                if b < NUM_BINS:
                    hist[int(b)] = c

            data = dict(zip(BIN_COLS, hist))
            data.update({
                "pkt_count": pkt_count, "syn_count": syn_count, "ack_count": ack_count,
                "udp_count": udp_count, "tcp_count": tcp_count, "dns_udp_count": dns_udp_count,
                "syn_only_count": syn_noack_count,
                "protocol": "UDP" if udp_count >= tcp_count else "TCP",
                "dst_port": 53 if dns_udp_count > 0 else 0,
                "dns_query_matched": 0 if dns_udp_count > 0 else 1,
            })
            return pd.Series(data)

        result = grouped.apply(agg_one, include_groups=False).reset_index()
        all_rows.append(result)

    df = pd.concat(all_rows, ignore_index=True)

    def attack_type(row):
        if row["src_ip"] != ATTACKER_IP:
            return "benign"
        if row["syn_only_count"] > row["udp_count"] and row["syn_only_count"] > 0:
            return "syn"
        return "udp"

    df["attack_type"] = df.apply(attack_type, axis=1)
    df["label"] = (df["attack_type"] != "benign").astype(int)
    print(f"[all_baselines_windowed] aggregated {len(df)} window-rows in {time.time() - t0:.1f}s")
    print(f"[all_baselines_windowed] attack_type distribution:\n{df['attack_type'].value_counts()}")

    cache_path = os.path.join(REPO_ROOT, "evaluation_output", f"windowed_baseline_dataset_{window_seconds}s.csv")
    df.to_csv(cache_path, index=False)
    print(f"[all_baselines_windowed] cached windowed dataset to {cache_path}")
    return df


def _per_type_metrics(test_df, y_pred):
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
    return per_type


def score(name, y_test, y_pred, test_df, memory_bytes):
    cm = confusion_matrix(y_test, y_pred)
    overall = classification_report(y_test, y_pred, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)
    per_type = _per_type_metrics(test_df, y_pred)

    print(f"\n=== {name} @ {WINDOW_SECONDS}s fixed window (real, apples-to-apples) ===")
    print(f"confusion matrix:\n{cm}")
    print(f"accuracy={overall['accuracy']:.4f}  attack: precision={overall['attack']['precision']:.3f} "
          f"recall={overall['attack']['recall']:.3f} f1={overall['attack']['f1-score']:.3f}  "
          f"weighted_f1={overall['weighted avg']['f1-score']:.3f}  fpr={cm[0][1] / (cm[0][1] + cm[0][0]):.3f}")
    for atype, rep in per_type.items():
        print(f"  {atype}-vs-benign: precision={rep['precision']:.3f} recall={rep['recall']:.3f} f1={rep['f1']:.3f}")

    return {
        "system": name, "accuracy": overall["accuracy"], "precision": overall["weighted avg"]["precision"],
        "recall": overall["weighted avg"]["recall"], "f1": overall["weighted avg"]["f1-score"],
        "attack_f1": overall["attack"]["f1-score"], "fpr": cm[0][1] / (cm[0][1] + cm[0][0]),
        "memory_bytes": memory_bytes, "per_attack_type": per_type,
    }


def main():
    df = build_windowed_dataset(WINDOW_SECONDS)
    train_df, test_df = per_type_temporal_split(df)
    y_test = test_df["label"].to_numpy()

    results = []

    y_pred = jaqen_lite.predict(test_df)
    results.append(score("Jaqen-lite (windowed)", y_test, y_pred, test_df,
                          jaqen_lite.memory_footprint().bytes_total))

    y_pred = poseidon_lite.predict(test_df)
    results.append(score("POSEIDON-lite (windowed)", y_test, y_pred, test_df,
                          poseidon_lite.memory_footprint().bytes_total))

    X_train, y_train = train_df[BIN_COLS].to_numpy(), train_df["label"].to_numpy()
    X_test = test_df[BIN_COLS].to_numpy()
    clf = RandomForestClassifier(n_estimators=100, max_depth=None, random_state=0, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    results.append(score("FlowLens-lite (windowed)", y_test, y_pred, test_df, 1024 * NUM_BINS * 2))

    out_path = os.path.join(REPO_ROOT, "evaluation_output", "all_baselines_windowed.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[all_baselines_windowed] wrote {out_path}")


if __name__ == "__main__":
    main()
