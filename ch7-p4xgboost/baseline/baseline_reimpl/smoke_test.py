#!/usr/bin/env python3
"""
smoke_test.py -- generates a SYNTHETIC labelled flow table with the schema
expected by evaluate_baselines.py, and runs the full pipeline against it.

THIS IS NOT THESIS DATA. Its only purpose is to catch code errors (schema
mismatches, crashes, obviously-broken logic) before you point
evaluate_baselines.py at a real CIC-DDoS2019 export. Do not report these
numbers anywhere in the thesis.
"""
import numpy as np
import pandas as pd

from evaluate_baselines import evaluate, to_markdown_table

RNG = np.random.default_rng(42)
N_BENIGN = 4000
N_ATTACK = 1000


def make_benign_flows(n):
    return pd.DataFrame({
        "timestamp": np.sort(RNG.uniform(0, 1000, n)),
        "protocol": RNG.choice(["TCP", "UDP"], size=n, p=[0.7, 0.3]),
        "syn_count": RNG.poisson(2, n),
        "ack_count": RNG.poisson(2, n),
        "pkt_count": RNG.poisson(20, n) + 5,
        "udp_count": RNG.poisson(5, n),
        "dst_port": RNG.choice([80, 443, 22, 53], size=n),
        "dns_query_matched": RNG.choice([0, 1], size=n, p=[0.05, 0.95]),
        "pkt_lengths": [list(RNG.normal(600, 150, size=RNG.integers(5, 30)).clip(40, 1500).astype(int))
                        for _ in range(n)],
        "label": 0,
    })


def make_attack_flows(n):
    # crude synthetic attack signatures: SYN floods (high syn, low ack),
    # UDP floods (high udp_count), unmatched DNS replies
    kind = RNG.choice(["syn_flood", "udp_flood", "dns_amp"], size=n)
    syn = np.where(kind == "syn_flood", RNG.integers(50, 200, n), RNG.poisson(2, n))
    ack = np.where(kind == "syn_flood", RNG.integers(0, 5, n), RNG.poisson(2, n))
    udp = np.where(kind == "udp_flood", RNG.integers(80, 300, n), RNG.poisson(5, n))
    dns_matched = np.where(kind == "dns_amp", 0, RNG.choice([0, 1], size=n, p=[0.05, 0.95]))
    proto = np.where(np.isin(kind, ["udp_flood", "dns_amp"]), "UDP", "TCP")
    dst_port = np.where(kind == "dns_amp", 53, RNG.choice([80, 443], size=n))
    pkt_count = np.where(kind == "syn_flood", syn + ack, RNG.poisson(40, n) + 20)

    return pd.DataFrame({
        "timestamp": np.sort(RNG.uniform(0, 1000, n)),
        "protocol": proto,
        "syn_count": syn,
        "ack_count": ack,
        "pkt_count": pkt_count,
        "udp_count": udp,
        "dst_port": dst_port,
        "dns_query_matched": dns_matched,
        "pkt_lengths": [list(RNG.normal(80, 20, size=RNG.integers(20, 80)).clip(40, 1500).astype(int))
                        for _ in range(n)],
        "label": 1,
    })


def main():
    df = pd.concat([make_benign_flows(N_BENIGN), make_attack_flows(N_ATTACK)], ignore_index=True)
    df = df.sample(frac=1.0, random_state=1).reset_index(drop=True)  # shuffle rows,
                                                                        # keep timestamp col intact
                                                                        # for the temporal split

    print(f"Synthetic dataset: {len(df)} flows ({df['label'].mean()*100:.1f}% attack)")
    print("=" * 70)
    print("SMOKE TEST ONLY -- synthetic data, not thesis results")
    print("=" * 70)

    results = evaluate(df, ts_col="timestamp")
    print(results.to_string(index=False))

    md = to_markdown_table(results, p4xgboost_row=None)
    out_path = "../results/smoke_test_output.md"
    with open(out_path, "w") as f:
        f.write("# SMOKE TEST OUTPUT -- SYNTHETIC DATA, NOT THESIS RESULTS\n\n" + md)
    print(f"\nWrote {out_path} (synthetic smoke-test output only)")


if __name__ == "__main__":
    main()
