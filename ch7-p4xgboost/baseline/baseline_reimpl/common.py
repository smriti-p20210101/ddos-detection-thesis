"""
common.py -- shared utilities for the offline functional-metric evaluation
harness. This module mirrors, in pure Python, exactly the data-plane logic
of each *_lite.p4 program so that the same detection/classification
decisions can be batch-scored against a labelled CIC-DDoS2019 flow table
without needing a live Mininet/BMv2 run for every experiment.

Expected input schema (see README.md "How to use this with real
CIC-DDoS2019 data"):
    src_ip, dst_ip, src_port, dst_port, protocol,
    syn_count, ack_count, fin_count, rst_count,
    pkt_lengths (list[int] or already-binned histogram columns bin_0..bin_9),
    flow_duration, inter_arrival_mean, inter_arrival_std,
    timestamp (for the temporal 80/20 split), label (0=benign, 1=attack)
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

import numpy as np
import pandas as pd

REG_SIZE = 1024  # must match REG_SIZE in the .p4 files, for a like-for-like
                   # memory-footprint comparison with P4-XGBoost's 1024-entry CMS


def crc16_index(value: int, size: int = REG_SIZE) -> int:
    """Stand-in for the P4 `hash(idx, HashAlgorithm.crc16, ...)` call used in
    all three *_lite.p4 programs. Uses Python's zlib.crc32 truncated to 16
    bits (functionally equivalent hash-collision behaviour to CRC16 for the
    purposes of this comparison; not bit-identical to a hardware CRC16
    ALU -- flag this if you need exact collision parity with a compiled P4
    program)."""
    import zlib

    return zlib.crc32(str(value).encode()) % size


def temporal_split(df: pd.DataFrame, ts_col: str = "timestamp", train_frac: float = 0.8):
    """Mirrors the exact split used for P4-XGBoost in Ch7 §7.6.3: 'the first
    80% of the capture duration is used exclusively for training and the
    final 20% for testing.'"""
    df_sorted = df.sort_values(ts_col).reset_index(drop=True)
    cutoff = int(len(df_sorted) * train_frac)
    return df_sorted.iloc[:cutoff].copy(), df_sorted.iloc[cutoff:].copy()


def ensure_bin_histogram(df: pd.DataFrame, num_bins: int = 10, quant_shift: int = 4) -> pd.DataFrame:
    """Builds bin_0..bin_{num_bins-1} columns (FlowLens-lite's flow marker)
    from a `pkt_lengths` column of per-flow packet-length lists, if the
    caller's CSV doesn't already provide pre-binned histogram columns.
    Mirrors flowlens_lite.p4: bin(QL, PL) = PL >> QL, truncated to the first
    num_bins quantized bins."""
    bin_cols = [f"bin_{i}" for i in range(num_bins)]
    if all(c in df.columns for c in bin_cols):
        return df

    def make_hist(pkt_lengths):
        hist = np.zeros(num_bins, dtype=np.float64)
        if pkt_lengths is None:
            return hist
        # A CSV round-trip stores a per-row Python list as its string repr
        # (e.g. "[74.0, 66.0, ...]") -- pd.read_csv gives back that literal
        # string, not a real list, so parse it back before iterating.
        if isinstance(pkt_lengths, str):
            import ast
            try:
                pkt_lengths = ast.literal_eval(pkt_lengths)
            except (ValueError, SyntaxError):
                return hist
        for pl in pkt_lengths:
            b = int(pl) >> quant_shift
            if b < num_bins:
                hist[b] += 1
        return hist

    hists = df["pkt_lengths"].apply(make_hist)
    hist_df = pd.DataFrame(hists.tolist(), columns=bin_cols, index=df.index)
    return pd.concat([df, hist_df], axis=1)


@dataclass
class MemoryFootprint:
    """Reported alongside accuracy metrics per the Stage-2/Option-A scope
    (functional metrics only, no throughput/latency)."""
    name: str
    bytes_total: int
    breakdown: str

    def as_dict(self):
        return {"system": self.name, "memory_bytes": self.bytes_total, "breakdown": self.breakdown}
