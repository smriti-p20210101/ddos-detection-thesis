#!/usr/bin/env python3
"""
extract_features.py -- builds the flow-level schema required by
evaluate_baselines.py (see README.md) from a raw per-packet CIC-DDoS2019
CSV/pcap-derived table.

If you already have CICFlowMeter-style flow CSVs (as used for the Ch7
XGBoost pipeline), you likely already have most of these columns under
different names -- map them directly rather than re-deriving from packets;
see the `--from-cicflowmeter` mode below.

Expected raw packet columns: timestamp, src_ip, dst_ip, src_port, dst_port,
protocol, pkt_len, tcp_syn, tcp_ack, tcp_fin, tcp_rst, label
"""
import argparse

import numpy as np
import pandas as pd


def _flow_attack_type(types) -> str:
    """A flow's real attack type: if any packet in it was flagged "syn",
    the flow is "syn" (a SYN-flood attempt on that 5-tuple); elif any
    packet was "udp", the flow is "udp"; else "benign". Real packet-level
    signal aggregated up to the flow, not assumed from the flow's source
    alone -- matches controller/ml/train_model.py's per-window logic."""
    if types is None:
        return "benign"
    values = set(types)
    if "syn" in values:
        return "syn"
    if "udp" in values:
        return "udp"
    return "benign"


def from_packets(pkt_df: pd.DataFrame) -> pd.DataFrame:
    """Vectorized flow aggregation. An earlier version called one Python
    function per distinct flow via groupby(...).apply() -- fine for a
    small file, but a single large UDP-flood file can have tens of
    thousands of distinct 5-tuple flows (this attacker sweeps across many
    destination ports), and per-group Python calls at that scale took over
    30 minutes for a single file with no end in sight. Rewritten to use
    pandas' C-level groupby aggregation for every field except the
    genuinely list-shaped pkt_lengths column, which is isolated into its
    own single-column .apply() rather than bundled into a 12-field
    per-group function call."""
    group_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
    df = pkt_df.copy()

    for col in ["tcp_syn", "tcp_ack", "tcp_fin", "tcp_rst"]:
        if col not in df.columns:
            df[col] = 0
    if "attack_type" not in df.columns:
        df["attack_type"] = "benign"
    df["is_udp_proto"] = df["protocol"].astype(str).str.upper() == "UDP"
    df["is_syn_flow"] = df["attack_type"] == "syn"
    df["is_udp_flow"] = df["attack_type"] == "udp"

    grouped = df.groupby(group_cols, sort=False)

    agg = grouped.agg(
        timestamp=("timestamp", "min"),
        _ts_max=("timestamp", "max"),
        pkt_count=("timestamp", "size"),
        syn_count=("tcp_syn", "sum"),
        ack_count=("tcp_ack", "sum"),
        fin_count=("tcp_fin", "sum"),
        rst_count=("tcp_rst", "sum"),
        _is_udp_proto_any=("is_udp_proto", "any"),
        label=("label", "max"),
        _has_syn=("is_syn_flow", "any"),
        _has_udp=("is_udp_flow", "any"),
    ).reset_index()

    agg["flow_duration"] = agg["_ts_max"] - agg["timestamp"]
    agg["udp_count"] = (agg["pkt_count"] * agg["_is_udp_proto_any"]).astype(int)
    agg["dns_query_matched"] = 1
    agg["attack_type"] = np.where(agg["_has_syn"], "syn", np.where(agg["_has_udp"], "udp", "benign"))
    agg["label"] = agg["label"].astype(int)

    # inter-arrival stats without a per-group Python call: sort by group +
    # time, diff globally, then blank out the first row of each group
    # (where the diff crosses a flow boundary) before averaging per group.
    df_sorted = df.sort_values(group_cols + ["timestamp"])
    ts_diff = df_sorted.groupby(group_cols, sort=False)["timestamp"].diff()
    df_sorted = df_sorted.assign(_ts_diff=ts_diff)
    inter_arrival = df_sorted.groupby(group_cols, sort=False)["_ts_diff"].agg(["mean", "std"]).reset_index()
    inter_arrival = inter_arrival.rename(columns={"mean": "inter_arrival_mean", "std": "inter_arrival_std"})
    inter_arrival[["inter_arrival_mean", "inter_arrival_std"]] = \
        inter_arrival[["inter_arrival_mean", "inter_arrival_std"]].fillna(0.0)

    # pkt_lengths is inherently list-shaped -- kept as its own lightweight
    # single-column groupby rather than folded into the big agg() above.
    pkt_lengths = grouped["pkt_len"].apply(list).reset_index(name="pkt_lengths")

    flows = agg.merge(inter_arrival, on=group_cols).merge(pkt_lengths, on=group_cols)
    return flows.drop(columns=["_ts_max", "_is_udp_proto_any", "_has_syn", "_has_udp"])


def from_cicflowmeter(cfm_df: pd.DataFrame, column_map: dict) -> pd.DataFrame:
    """Rename CICFlowMeter columns to the schema evaluate_baselines.py
    expects. `column_map` example:
        {
            "Timestamp": "timestamp",
            "SYN Flag Count": "syn_count",
            "ACK Flag Count": "ack_count",
            "Protocol": "protocol",
            "Destination Port": "dst_port",
            "Label": "label",
        }
    Note: CICFlowMeter doesn't export a raw packet-length list, so
    `pkt_lengths` must be reconstructed from its packet-length
    min/mean/max/std columns as a synthetic per-flow sample if you don't
    have the original pcaps -- see the `synthesize_pkt_lengths` helper below.
    """
    out = cfm_df.rename(columns=column_map)
    if "pkt_lengths" not in out.columns:
        out["pkt_lengths"] = out.apply(synthesize_pkt_lengths, axis=1)
    return out


def synthesize_pkt_lengths(row, n_samples: int = 20):
    """Approximates a per-flow packet-length distribution from CICFlowMeter's
    summary statistics (mean/std/min/max) when raw packet lengths aren't
    available. This is a lossy approximation -- prefer real per-packet
    pcaps for flowlens_lite.py's histogram features if at all possible."""
    import numpy as np

    mean = row.get("Packet Length Mean", row.get("Fwd Packet Length Mean", 500))
    std = row.get("Packet Length Std", row.get("Fwd Packet Length Std", 100))
    lo = row.get("Min Packet Length", 40)
    hi = row.get("Max Packet Length", 1500)
    return list(np.random.normal(mean, max(std, 1), n_samples).clip(lo, hi).astype(int))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--mode", choices=["packets", "cicflowmeter"], default="packets")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    raw = pd.read_csv(args.input)
    if args.mode == "packets":
        flows = from_packets(raw)
    else:
        # Fill in your dataset's actual CICFlowMeter column names here.
        column_map = {
            "Timestamp": "timestamp",
            "SYN Flag Count": "syn_count",
            "ACK Flag Count": "ack_count",
            "Protocol": "protocol",
            "Destination Port": "dst_port",
            "Label": "label",
        }
        flows = from_cicflowmeter(raw, column_map)

    flows.to_csv(args.out, index=False)
    print(f"Wrote {len(flows)} flows to {args.out}")
