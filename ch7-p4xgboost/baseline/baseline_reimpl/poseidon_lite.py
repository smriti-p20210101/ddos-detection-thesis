"""
poseidon_lite.py -- offline equivalent of p4/poseidon_lite.p4's ingress
logic (POSEIDON's Fig. 4 SYN-flood policy + Fig. 5 DNS-amplification
policy), for batch scoring against a labelled CIC-DDoS2019 flow table.

The "sproxy gray area" (verdict==2 in the P4 program) is resolved here by
the SoftwareSynProxy cookie-verification logic from
controller/poseidon_controller.py, applied offline: since CIC-DDoS2019 flow
records don't carry a raw cookie exchange, we approximate the gray-area
resolution as "attack unless the flow shows the completed 3-way handshake
signature (SYN, SYN-ACK-equivalent ACK count == 1, and further data
packets)", which is the same signal POSEIDON's own SYN-proxy verifies via
cookie round-trip.
"""
import numpy as np
import pandas as pd

from common import REG_SIZE, MemoryFootprint

SYN_ACK_ASYM_T = 15
DNS_RATE_LIMIT = 100  # packets / window, meter threshold equivalent


def predict(df: pd.DataFrame) -> np.ndarray:
    preds = np.zeros(len(df), dtype=int)

    is_tcp = (df["protocol"].astype(str).str.upper() == "TCP").to_numpy()
    syn = df["syn_count"].to_numpy()
    ack = df["ack_count"].to_numpy()

    asym = syn - ack
    drop_mask = is_tcp & (asym > SYN_ACK_ASYM_T)            # Fig.4 line 4-5: drop
    pass_mask = is_tcp & (syn == ack)                        # Fig.4 line 6-7: pass
    gray_mask = is_tcp & ~drop_mask & ~pass_mask              # Fig.4 line 8-9: sproxy

    # sproxy gray-area resolution (offline approximation of cookie check):
    # flag as attack if the flow never completes a full handshake pattern
    # (no data packets beyond the SYN/ACK exchange).
    completes_handshake = df.get("pkt_count", pd.Series(np.zeros(len(df)))).to_numpy() > (syn + ack)
    gray_attack = gray_mask & ~completes_handshake

    preds[drop_mask] = 1
    preds[gray_attack] = 1

    # DNS amplification policy (Fig. 5): unmatched or excessive-rate DNS
    # replies are attacks.
    is_udp_dns = (
        (df["protocol"].astype(str).str.upper() == "UDP")
        & (df.get("dst_port", pd.Series(np.zeros(len(df)))) == 53)
    ).to_numpy()
    dns_unmatched = df.get("dns_query_matched", pd.Series(np.ones(len(df)))).to_numpy() == 0
    dns_over_rate = df.get("udp_count", pd.Series(np.zeros(len(df)))).to_numpy() > DNS_RATE_LIMIT
    preds[is_udp_dns & (dns_unmatched | dns_over_rate)] = 1

    return preds


def memory_footprint() -> MemoryFootprint:
    """2 registers (syn_count, ack_count) + 1 dns_query_seen bit-register,
    all sized REG_SIZE, plus a meter (approximated as REG_SIZE x 32b for the
    functional comparison, matching a BMv2 meter's per-flow state)."""
    bytes_total = 2 * REG_SIZE * 4 + REG_SIZE // 8 + REG_SIZE * 4
    return MemoryFootprint(
        name="POSEIDON-lite",
        bytes_total=bytes_total,
        breakdown=(
            f"2x{REG_SIZE}x32b (syn/ack counters) + {REG_SIZE}x1b (dns query cache) "
            f"+ {REG_SIZE}x32b (rlimit meter state)"
        ),
    )
