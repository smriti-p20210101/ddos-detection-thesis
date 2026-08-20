"""
jaqen_lite.py -- offline equivalent of p4/jaqen_lite.p4's ingress logic, for
batch scoring against a labelled CIC-DDoS2019 flow table. No training is
involved (Jaqen's detector is threshold-based, not learned), so this module
only exposes `predict()` and `memory_footprint()`.

Thresholds are module-level constants so they can be swept/tuned exactly
like the P4 constants SYN_THRESH / UDP_THRESH / ASYM_THRESH; keep them in
sync with p4/jaqen_lite.p4 if you change one.
"""
import numpy as np
import pandas as pd

from common import REG_SIZE, MemoryFootprint

SYN_THRESH = 20
UDP_THRESH = 50
ASYM_THRESH = 15


def predict(df: pd.DataFrame) -> np.ndarray:
    """Per-flow binary prediction (1=attack, 0=benign), mirroring
    jaqen_lite.p4's `apply` block exactly:
        if syn_val > SYN_THRESH and (syn_val - ack_val) > ASYM_THRESH: attack
        elif udp_val > UDP_THRESH: attack
        else: benign
    """
    syn = df["syn_count"].to_numpy()
    ack = df["ack_count"].to_numpy()
    is_udp = (df["protocol"].astype(str).str.upper() == "UDP").to_numpy()
    udp_count = df.get("udp_count", df.get("pkt_count", pd.Series(np.zeros(len(df))))).to_numpy()

    syn_asym = (syn > SYN_THRESH) & ((syn - ack) > ASYM_THRESH)
    udp_heavy = is_udp & (udp_count > UDP_THRESH)

    return (syn_asym | udp_heavy).astype(int)


def memory_footprint() -> MemoryFootprint:
    """3 registers (syn_count, ack_count, udp_count) x REG_SIZE x 32 bits,
    plus 1 dedup bit-register x REG_SIZE x 1 bit -- matches the comment in
    p4/jaqen_lite.p4."""
    bytes_total = 3 * REG_SIZE * 4 + REG_SIZE // 8
    return MemoryFootprint(
        name="Jaqen-lite",
        bytes_total=bytes_total,
        breakdown=f"3x{REG_SIZE}x32b (syn/ack/udp counters) + {REG_SIZE}x1b (dedup)",
    )
