from __future__ import annotations

"""Offline pipeline: extract real 8D feature vectors from real CIC-DDoS2019
PCAP data (now spanning two real attack types) and train a real XGBoost
model on them.

Dataset scope (v2, combined UDP+SYN):
  - 111 files spread evenly across PCAPs/01-12/PCAP-01-12_0-0249.zip
    (chunk 1, files _0.._0249) -- real sustained UDP flood throughout.
  - All 69 files of PCAPs/01-12/PCAP-01-12_0750-0818.zip (chunk 4,
    files _0750.._0818) -- a real SYN flood emerges in the last few files
    of this chunk (confirmed via forensic scan: SYN-only packet counts to
    172.16.0.5->192.168.50.1:80/22 ramp from single digits to 3,830 in
    file _0817). Files _0750-_0809ish are mostly UDP continuation.

Label ground truth: 172.16.0.5 is the confirmed attacker (forensic
inspection, see build tracker stage #7). Each (src_ip, 0.5s window) is now
labeled with a real attack TYPE, not just binary malicious/benign: "udp" if
the attacker's traffic in that window is UDP-dominant, "syn" if it's
dominated by TCP SYN-without-ACK packets, "benign" for every non-attacker
window. Determined per-window from real packet content, not assumed from
which chunk/file it came from.

Split methodology -- a real, documented deviation from a naive single
global temporal split: because the real SYN data is concentrated in the
last handful of files in the whole capture, a strict "first 80% of
capture-time = train" split would put almost all SYN examples in the test
set and none in training -- the model could never learn to recognize SYN
at all, not because the system can't detect it, but because a pure
time-ordered split starves it of examples. Instead: each attack type
(benign / udp / syn) is split 80/20 by time WITHIN that type, then the
three 80% portions are combined into train and the three 20% portions into
test. Still chronological within each type, not randomly shuffled -- just
applied per-type so both real attack types are genuinely represented in
both splits. Documented here rather than silently deviating from the
thesis's stated "first 80% of capture duration" wording.

Resumability: each file's RAW per-packet export is cached individually
(evaluation_output/raw_packet_cache/<file>.csv) so an interrupted run
(e.g. the host machine restarting, which kills the WSL2 VM entirely) can
resume by skipping files already cached, not reprocessing from scratch.
The raw cache is window-size-independent (tshark's per-packet export
doesn't depend on window size, only the aggregation step does), so
re-aggregating at a different window size or with different derived
features never needs to re-run tshark -- see scripts/window_sweep.py and
scripts/feature_engineering_sweep.py, both of which reuse this same cache.

Feature set (v3, 10D): a real evaluation (scripts/feature_engineering_sweep.py)
found the model conflated real TCP handshake SYNs with attack SYN-flood
packets via the single generic tcp_flags (SYN fraction) feature alone.
Adding syn_noack_ratio (fraction of a window's packets that are
SYN-without-ACK -- already computed for real attack-type ground-truth
labeling below, but not previously exposed to the model) and ack_ratio
raised real accuracy from 83.46% to 86.22% on the SAME 0.5s window --
i.e. with no real detection-latency cost, unlike widening the window
(also real-tested; window size up to 4.0s raised accuracy further but at
a real, disclosed latency cost -- see evaluation_output/window_sweep_results.json).
Hyperparameters were also retuned via a leakage-safe CV search (3-fold,
train-split only; scripts/tune_model_search.py) to max_depth=9,
learning_rate=0.2 (from the thesis's original depth=6, lr=0.1).
"""

import glob
import io
import json
import os
import subprocess
import sys
import time

import numpy as np
import pandas as pd
import xgboost as xgb
import yaml
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

ATTACKER_IP = "172.16.0.5"
WINDOW_SECONDS = 0.5
CHUNK1_DIR = "/mnt/d/Smriti PhD/extracted_sample"
CHUNK1_ZIP = "/mnt/d/Smriti PhD/PCAP-01-12_0-0249.zip"
CHUNK4_DIR = "/mnt/d/Smriti PhD/extracted_sample_chunk4"
CHUNK4_ZIP = "/mnt/d/Smriti PhD/PCAP-01-12_0750-0818.zip"
RAW_CACHE_DIR_NAME = "raw_packet_cache"  # window-size-independent, see module docstring
FEATURE_COLUMNS = ["pkt_rate", "byte_rate", "duration", "proto_var", "port_div",
                    "size_var", "tcp_flags", "inter_arrival", "syn_noack_ratio", "ack_ratio"]
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ip.proto", "tcp.dstport", "udp.dstport",
    "frame.len", "tcp.flags.syn", "tcp.flags.ack",
]


def _select_files() -> list[tuple[str, str, str]]:
    """Returns (filename, local_dir, source_zip) for the full real
    dataset scope: 111 spread files from chunk 1 + all 69 files of
    chunk 4."""
    chunk1_indices = sorted(set(np.linspace(0, 249, 111, dtype=int).tolist()))
    chunk1_files = [
        (f"SAT-01-12-2018_0{i}" if i > 0 else "SAT-01-12-2018_0", CHUNK1_DIR, CHUNK1_ZIP)
        for i in chunk1_indices
    ]
    chunk4_files = [
        (f"SAT-01-12-2018_0{i}", CHUNK4_DIR, CHUNK4_ZIP)
        for i in range(750, 819)
    ]
    return chunk1_files + chunk4_files


def _ensure_extracted(fname: str, local_dir: str, zip_path: str) -> str:
    fpath = os.path.join(local_dir, fname)
    if not os.path.exists(fpath):
        os.makedirs(local_dir, exist_ok=True)
        subprocess.run(["unzip", "-o", "-q", zip_path, fname], cwd=local_dir, check=True)
    return fpath


def _tshark_export_raw(fpath: str) -> pd.DataFrame:
    """Raw per-packet export -- deliberately WITHOUT a window column, so the
    result is window-size-independent and reusable for any window size or
    derived feature without re-running tshark (the real dominant cost of
    extraction; see module docstring)."""
    cmd = ["tshark", "-r", fpath, "-T", "fields"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "separator=,", "-E", "occurrence=f"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    # file _0818 is a real truncated capture (tshark warns "cut short in the
    # middle of a packet") -- process whatever it did manage to read rather
    # than failing the whole run on a nonzero exit code.
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


def _aggregate_windows(df: pd.DataFrame, window_seconds: float = WINDOW_SECONDS) -> pd.DataFrame:
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


def _build_raw_cache() -> None:
    """Populates evaluation_output/raw_packet_cache/ (idempotent, resumable
    -- skips files already cached). This is the real ~50-minute-dominant
    cost of extraction; every window size or feature set tested afterward
    reuses this cache instead of re-running tshark."""
    targets = _select_files()
    cache_dir = os.path.join(REPO_ROOT, "evaluation_output", RAW_CACHE_DIR_NAME)
    os.makedirs(cache_dir, exist_ok=True)
    run_start = time.time()
    for i, (fname, local_dir, zip_path) in enumerate(targets):
        cache_path = os.path.join(cache_dir, f"{fname}.csv")
        t0 = time.time()
        if os.path.exists(cache_path):
            source = "cache"
        else:
            fpath = _ensure_extracted(fname, local_dir, zip_path)
            raw = _tshark_export_raw(fpath)
            raw.to_csv(cache_path, index=False)
            source = "extracted"
        elapsed = time.time() - t0
        total_elapsed = time.time() - run_start
        print(f"[raw_cache] ({i + 1}/{len(targets)}) {fname} [{source}, {elapsed:.1f}s this file, "
              f"{total_elapsed / 60:.1f}min total]")


def extract_dataset(window_seconds: float = WINDOW_SECONDS) -> pd.DataFrame:
    targets = _select_files()
    print(f"[extract] {len(targets)} real pcap files targeted "
          f"({sum(1 for _, d, _ in targets if d == CHUNK1_DIR)} from chunk 1, "
          f"{sum(1 for _, d, _ in targets if d == CHUNK4_DIR)} from chunk 4)")

    _build_raw_cache()

    cache_dir = os.path.join(REPO_ROOT, "evaluation_output", RAW_CACHE_DIR_NAME)
    all_rows = []
    run_start = time.time()
    for i, (fname, _, _) in enumerate(targets):
        raw = pd.read_csv(os.path.join(cache_dir, f"{fname}.csv"))
        raw["window"] = (raw["ts"] // window_seconds).astype(np.int64)
        windows = _aggregate_windows(raw, window_seconds)
        all_rows.append(windows)
        if (i + 1) % 30 == 0 or i + 1 == len(targets):
            print(f"[extract] aggregated ({i + 1}/{len(targets)}) files, "
                  f"{(time.time() - run_start):.1f}s so far")

    df = pd.concat(all_rows, ignore_index=True)
    print(f"[extract] done in {(time.time() - run_start) / 60:.1f} min. {len(df)} labeled window-rows")
    print(f"[extract] attack_type distribution:\n{df['attack_type'].value_counts()}")
    return df


def load_ml_hyperparams() -> dict:
    with open(os.path.join(REPO_ROOT, "config", "settings.yaml")) as f:
        settings = yaml.safe_load(f)
    return settings["settings"]["ml"]


def per_type_temporal_split(df: pd.DataFrame, train_fraction: float = 0.8):
    """Splits each attack_type (benign/udp/syn) 80/20 by time WITHIN that
    type, then combines. See module docstring for why a single global
    temporal split doesn't work here (SYN data is concentrated at the very
    end of the capture and would be almost entirely excluded from
    training)."""
    train_parts, test_parts = [], []
    for atype, group in df.groupby("attack_type"):
        g_sorted = group.sort_values("window").reset_index(drop=True)
        cutoff = int(len(g_sorted) * train_fraction)
        train_parts.append(g_sorted.iloc[:cutoff])
        test_parts.append(g_sorted.iloc[cutoff:])
    train_df = pd.concat(train_parts, ignore_index=True)
    test_df = pd.concat(test_parts, ignore_index=True)
    return train_df, test_df


def train_and_evaluate(df: pd.DataFrame) -> xgb.XGBClassifier:
    params = load_ml_hyperparams()
    print(f"[train] hyperparameters from config/settings.yaml: {params}")

    train_df, test_df = per_type_temporal_split(df)
    print(f"[train] per-type temporal 80/20 split: {len(train_df)} train rows, {len(test_df)} test rows")
    print(f"[train] train attack_type distribution:\n{train_df['attack_type'].value_counts()}")
    print(f"[train] test attack_type distribution:\n{test_df['attack_type'].value_counts()}")

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
    overall_report = classification_report(y_test, y_pred, target_names=["benign", "attack"],
                                            digits=3, output_dict=True)
    print(f"[train] overall confusion matrix:\n{cm}")
    print(f"[train] overall report:\n{json.dumps(overall_report, indent=2)}")

    # Per-attack-type breakdown (Table 7.4 style): for each real attack
    # type, score it against the benign rows in the same test set.
    per_type = {}
    for atype in ["udp", "syn"]:
        mask = test_df["attack_type"].isin(["benign", atype])
        if mask.sum() == 0 or (test_df.loc[mask, "attack_type"] == atype).sum() == 0:
            per_type[atype] = {"note": f"no real {atype} rows in this test split"}
            continue
        y_t = test_df.loc[mask, "label"]
        y_p = pd.Series(y_pred, index=test_df.index).loc[mask]
        rep = classification_report(y_t, y_p, target_names=["benign", "attack"],
                                     digits=3, output_dict=True, zero_division=0)
        per_type[atype] = rep
        print(f"[train] {atype}-vs-benign report:\n{json.dumps(rep, indent=2)}")

    model_path = os.path.join(REPO_ROOT, "controller", "ml", "model.json")
    model.save_model(model_path)
    print(f"[train] saved trained model to {model_path}")

    eval_path = os.path.join(REPO_ROOT, "evaluation_output", "train_eval_preview.json")
    with open(eval_path, "w") as f:
        json.dump({
            "train_rows": len(train_df), "test_rows": len(test_df),
            "confusion_matrix": cm.tolist(),
            "classification_report": overall_report,
            "per_attack_type": per_type,
            "split_method": "per-attack-type temporal 80/20 (see module docstring)",
        }, f, indent=2)
    print(f"[train] saved eval metrics to {eval_path}")

    return model


if __name__ == "__main__":
    out_path = os.path.join(REPO_ROOT, "evaluation_output", "extracted_features.csv")
    df = extract_dataset()
    df.to_csv(out_path, index=False)
    print(f"[extract] saved combined dataset to {out_path}")
    train_and_evaluate(df)
