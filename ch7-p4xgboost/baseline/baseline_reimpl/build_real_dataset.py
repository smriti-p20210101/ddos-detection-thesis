#!/usr/bin/env python3
"""Builds the real per-packet CSV this package's extract_features.py
--mode packets expects, from the same real CIC-DDoS2019 sample used for
the P4-XGBoost pipeline (see controller/ml/train_model.py's module
docstring for dataset scope and label-ground-truth reasoning).

v2: same 180-file scope as train_model.py (111 spread files from chunk 1's
UDP flood + all 69 files of chunk 4, where a real SYN flood was found in
the tail files) -- kept in sync so Table 7.6's baseline comparison and the
P4-XGBoost headline numbers are measured on the same real data, not two
different subsets. Also fixed here: tshark emits "True"/"False" text for
boolean flag fields, not "1"/"0" -- an earlier version of this function
silently zeroed every tcp_syn/tcp_ack/tcp_fin/tcp_rst value via
pd.to_numeric(errors="coerce").fillna(0). Fixed to string-match, same as
train_model.py.

Resumable: each file's extraction is cached individually
(real_packets_cache/<file>.csv) so an interrupted run can resume by
skipping files already cached.
"""
import io
import os
import subprocess
import time

import numpy as np
import pandas as pd

ATTACKER_IP = "172.16.0.5"
CHUNK1_DIR = "/mnt/d/Smriti PhD/extracted_sample"
CHUNK1_ZIP = "/mnt/d/Smriti PhD/PCAP-01-12_0-0249.zip"
CHUNK4_DIR = "/mnt/d/Smriti PhD/extracted_sample_chunk4"
CHUNK4_ZIP = "/mnt/d/Smriti PhD/PCAP-01-12_0750-0818.zip"

TSHARK_FIELDS = [
    "frame.time_epoch", "ip.src", "ip.dst", "ip.proto",
    "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
    "frame.len", "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin", "tcp.flags.reset",
]


def _select_files() -> list[tuple[str, str, str]]:
    """Same selection as controller/ml/train_model.py._select_files --
    kept in sync so both real pipelines measure the same real data."""
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


def _tshark_export(fpath: str) -> pd.DataFrame:
    cmd = ["tshark", "-r", fpath, "-T", "fields"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "separator=,", "-E", "occurrence=f"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    df = pd.read_csv(
        io.StringIO(result.stdout), header=None,
        names=["timestamp", "src_ip", "dst_ip", "proto_num", "tcp_sport", "udp_sport",
               "tcp_dport", "udp_dport", "pkt_len", "syn", "ack", "fin", "rst"],
        dtype=str,
    )
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip", "proto_num"])
    df["timestamp"] = df["timestamp"].astype(float)
    df["pkt_len"] = df["pkt_len"].astype(float)

    df["src_port"] = df["tcp_sport"].fillna(df["udp_sport"])
    df["dst_port"] = df["tcp_dport"].fillna(df["udp_dport"])
    proto_map = {"6": "TCP", "17": "UDP"}
    df["protocol"] = df["proto_num"].map(proto_map).fillna("OTHER")

    for flag_col, out_col in [("syn", "tcp_syn"), ("ack", "tcp_ack"), ("fin", "tcp_fin"), ("rst", "tcp_rst")]:
        df[out_col] = df[flag_col].fillna("False").isin(["True", "1", "1.0"]).astype(int)

    is_attacker = df["src_ip"] == ATTACKER_IP
    is_udp = df["protocol"] == "UDP"
    is_syn_only = (df["protocol"] == "TCP") & (df["tcp_syn"] == 1) & (df["tcp_ack"] == 0)
    df["attack_type"] = "benign"
    df.loc[is_attacker & is_udp, "attack_type"] = "udp"
    df.loc[is_attacker & is_syn_only, "attack_type"] = "syn"
    df["label"] = (df["attack_type"] != "benign").astype(int)

    return df[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
               "pkt_len", "tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst", "attack_type", "label"]]


def main():
    # Memory-safe by design: an earlier version of this function
    # accumulated all 180 files' raw packets (62.7M rows) into one
    # DataFrame and crashed with a real OOM ("Cannot allocate memory")
    # trying to write it as a single real_packets.csv -- caught only
    # because per-file caching meant no data was actually lost, just the
    # final merge step. Fixed by aggregating each file down to its (much
    # smaller) flow-level rows immediately, via extract_features.py's
    # from_packets(), and never holding more than one file's raw packets
    # in memory at a time. real_packets.csv (the giant per-packet file) is
    # no longer produced at all -- only the flow-level real_flows.csv,
    # which is what evaluate_baselines.py actually needs.
    from extract_features import from_packets

    targets = _select_files()
    cache_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_packets_cache")
    os.makedirs(cache_dir, exist_ok=True)

    print(f"[baseline-extract] {len(targets)} real pcap files targeted "
          f"({sum(1 for _, d, _ in targets if d == CHUNK1_DIR)} chunk1, "
          f"{sum(1 for _, d, _ in targets if d == CHUNK4_DIR)} chunk4)")

    all_flows = []
    run_start = time.time()
    for i, (fname, local_dir, zip_path) in enumerate(targets):
        cache_path = os.path.join(cache_dir, f"{fname}.csv")
        t0 = time.time()
        if os.path.exists(cache_path):
            raw = pd.read_csv(cache_path)
            source = "cache"
        else:
            fpath = _ensure_extracted(fname, local_dir, zip_path)
            raw = _tshark_export(fpath)
            raw.to_csv(cache_path, index=False)
            source = "extracted"

        flows = from_packets(raw)
        all_flows.append(flows)
        del raw  # free the raw-packet DataFrame immediately, only keep the much smaller flow rows

        elapsed = time.time() - t0
        total_elapsed = time.time() - run_start
        print(f"[baseline-extract] ({i + 1}/{len(targets)}) {fname} [{source}, {elapsed:.1f}s, "
              f"{total_elapsed / 60:.1f}min total]: {len(flows)} flows "
              f"(running total flows={sum(len(f) for f in all_flows)})")

    flows_df = pd.concat(all_flows, ignore_index=True)
    print(f"[baseline-extract] done in {(time.time() - run_start) / 60:.1f} min. "
          f"{len(flows_df)} total real flows")
    print(f"[baseline-extract] attack_type distribution:\n{flows_df['attack_type'].value_counts()}")

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "real_flows.csv")
    flows_df.to_csv(out_path, index=False)
    print(f"[baseline-extract] saved to {out_path}")


if __name__ == "__main__":
    main()
