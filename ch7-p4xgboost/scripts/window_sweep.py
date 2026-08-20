#!/usr/bin/env python3
"""Real window-size sweep for the combined UDP+SYN dataset.

The 0.5s window size in controller/ml/train_model.py was never itself
ablated -- this tests whether it's actually the best choice, or just the
thesis's original arbitrary pick.

Real engineering shortcut: tshark's raw per-packet export (the dominant
real cost of the ~50-minute extraction run) does not depend on window
size at all -- only the aggregation step does. So raw per-packet data is
cached ONCE per file (evaluation_output/raw_packet_cache/<file>.csv,
window-size-independent), and re-aggregated at whatever window size is
requested. First run (--build-cache) still costs ~50 real minutes (same
tshark work as before); every window size tested after that only re-runs
pandas aggregation + training, not tshark.

Aggregation logic is a direct copy of train_model.py's _aggregate_windows,
parametrized on window_seconds instead of the hardcoded constant -- kept
deliberately unchanged otherwise so results stay comparable. A sanity
check (--window-seconds 0.5) should reproduce train_eval_preview.json's
real 83.46% accuracy; if it doesn't, that's a real bug in this script, not
a real window-size effect, and is reported as such rather than trusted.
"""
import argparse
import io
import json
import os
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from controller.ml.train_model import (  # noqa: E402
    ATTACKER_IP, TSHARK_FIELDS, FEATURE_COLUMNS,
    _select_files, _ensure_extracted, load_ml_hyperparams, per_type_temporal_split,
)

RAW_CACHE_DIR = os.path.join(REPO_ROOT, "evaluation_output", "raw_packet_cache")
RESULTS_PATH = os.path.join(REPO_ROOT, "evaluation_output", "window_sweep_results.json")


def _tshark_export_raw(fpath: str) -> pd.DataFrame:
    """Same as train_model._tshark_export but without baking in a window
    column -- window assignment happens later, parametrized."""
    cmd = ["tshark", "-r", fpath, "-T", "fields"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "separator=,", "-E", "occurrence=f"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    df = pd.read_csv(
        io.StringIO(result.stdout), header=None,
        names=["ts", "src_ip", "proto", "tcp_dport", "udp_dport", "size", "syn_raw", "ack_raw"],
        dtype=str,
    )
    df = df.dropna(subset=["ts", "src_ip", "proto"])
    df["ts"] = df["ts"].astype(float)
    df["proto"] = df["proto"].astype(int)
    df["size"] = df["size"].astype(int)
    df["dst_port"] = pd.to_numeric(df["tcp_dport"], errors="coerce").fillna(
        pd.to_numeric(df["udp_dport"], errors="coerce")).fillna(0).astype(int)
    df["syn"] = df["syn_raw"].fillna("False").isin(["True", "1", "1.0"]).astype(int)
    df["ack"] = df["ack_raw"].fillna("False").isin(["True", "1", "1.0"]).astype(int)
    return df[["ts", "src_ip", "proto", "dst_port", "size", "syn", "ack"]]


def build_raw_cache():
    targets = _select_files()
    os.makedirs(RAW_CACHE_DIR, exist_ok=True)
    run_start = time.time()
    for i, (fname, local_dir, zip_path) in enumerate(targets):
        cache_path = os.path.join(RAW_CACHE_DIR, f"{fname}.csv")
        t0 = time.time()
        if os.path.exists(cache_path):
            source = "cache"
        else:
            fpath = _ensure_extracted(fname, local_dir, zip_path)
            raw = _tshark_export_raw(fpath)
            raw.to_csv(cache_path, index=False)
            source = "extracted"
        elapsed = time.time() - t0
        total = (time.time() - run_start) / 60
        print(f"[raw_cache] ({i + 1}/{len(targets)}) {fname} [{source}, {elapsed:.1f}s this file, {total:.1f}min total]")
    print(f"[raw_cache] done in {(time.time() - run_start) / 60:.1f} min. "
          f"{len(targets)} files cached to {RAW_CACHE_DIR}")


def _aggregate_windows_at(df: pd.DataFrame, window_seconds: float) -> pd.DataFrame:
    """Direct copy of train_model._aggregate_windows, parametrized on
    window_seconds instead of the module-level WINDOW_SECONDS constant."""
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
        syn_only_count = int(((g["proto"] == 6) & (g["syn"] == 1) & (g["ack"] == 0)).sum())

        return pd.Series({
            "pkt_rate": pkt_rate, "byte_rate": byte_rate, "duration": duration,
            "proto_var": 0.0 if pd.isna(proto_var) else proto_var, "port_div": port_div,
            "size_var": 0.0 if pd.isna(size_var) else size_var,
            "tcp_flags": tcp_flags, "inter_arrival": inter_arrival,
            "udp_count": udp_count, "syn_only_count": syn_only_count,
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


def build_dataset_at(window_seconds: float) -> pd.DataFrame:
    targets = _select_files()
    all_rows = []
    t0 = time.time()
    for fname, _, _ in targets:
        cache_path = os.path.join(RAW_CACHE_DIR, f"{fname}.csv")
        raw = pd.read_csv(cache_path)
        raw["window"] = (raw["ts"] // window_seconds).astype(np.int64)
        all_rows.append(_aggregate_windows_at(raw, window_seconds))
    df = pd.concat(all_rows, ignore_index=True)
    print(f"[window={window_seconds}s] aggregated {len(df)} window-rows in {time.time() - t0:.1f}s")
    print(f"[window={window_seconds}s] attack_type distribution:\n{df['attack_type'].value_counts()}")
    return df


def train_and_score(df: pd.DataFrame, window_seconds: float) -> dict:
    params = load_ml_hyperparams()
    train_df, test_df = per_type_temporal_split(df)
    X_train, y_train = train_df[FEATURE_COLUMNS], train_df["label"]
    X_test, y_test = test_df[FEATURE_COLUMNS], test_df["label"]

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
            per_type[atype] = {"note": f"no real {atype} rows in this test split"}
            continue
        y_t = test_df.loc[mask, "label"]
        y_p = pd.Series(y_pred, index=test_df.index).loc[mask]
        rep = classification_report(y_t, y_p, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)
        per_type[atype] = rep

    print(f"[window={window_seconds}s] confusion matrix:\n{cm}")
    print(f"[window={window_seconds}s] accuracy={overall['accuracy']:.4f}  "
          f"attack: precision={overall['attack']['precision']:.3f} recall={overall['attack']['recall']:.3f} "
          f"f1={overall['attack']['f1-score']:.3f}  weighted_f1={overall['weighted avg']['f1-score']:.3f}")
    for atype, rep in per_type.items():
        if "note" in rep:
            print(f"  {atype}: {rep['note']}")
        else:
            print(f"  {atype}-vs-benign: precision={rep['attack']['precision']:.3f} "
                  f"recall={rep['attack']['recall']:.3f} f1={rep['attack']['f1-score']:.3f}")

    result = {
        "window_seconds": window_seconds, "total_rows": len(df),
        "train_rows": len(train_df), "test_rows": len(test_df),
        "confusion_matrix": cm.tolist(), "accuracy": overall["accuracy"],
        "attack_precision": overall["attack"]["precision"], "attack_recall": overall["attack"]["recall"],
        "attack_f1": overall["attack"]["f1-score"], "weighted_f1": overall["weighted avg"]["f1-score"],
        "per_attack_type": {k: ({"note": v["note"]} if "note" in v else
                                 {"precision": v["attack"]["precision"], "recall": v["attack"]["recall"],
                                  "f1": v["attack"]["f1-score"]}) for k, v in per_type.items()},
    }

    existing = []
    if os.path.exists(RESULTS_PATH):
        with open(RESULTS_PATH) as f:
            existing = json.load(f)
    existing = [r for r in existing if r["window_seconds"] != window_seconds] + [result]
    existing.sort(key=lambda r: r["window_seconds"])
    with open(RESULTS_PATH, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"[window={window_seconds}s] wrote {RESULTS_PATH}")
    return result


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-cache", action="store_true", help="Build/verify the raw packet cache (one-time, ~50 real minutes)")
    ap.add_argument("--window-seconds", type=float, help="Aggregate + train + score at this window size")
    args = ap.parse_args()

    if args.build_cache:
        build_raw_cache()
    if args.window_seconds is not None:
        dataset = build_dataset_at(args.window_seconds)
        train_and_score(dataset, args.window_seconds)
    if not args.build_cache and args.window_seconds is None:
        ap.error("pass --build-cache and/or --window-seconds")
