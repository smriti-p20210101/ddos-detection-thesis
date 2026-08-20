#!/usr/bin/env python3
"""Real ablation: CMS register-width collision rate, computed over the
real distinct source IPs observed in our real extracted dataset. Uses the
same crc16-via-crc32 approximation baseline_reimpl/common.py already uses
and flags (not bit-identical to BMv2's real CRC16 hash extern)."""
import zlib

import pandas as pd

df = pd.read_csv("evaluation_output/extracted_features.csv")
distinct_ips = df["src_ip"].unique()
print(f"real distinct source IPs in dataset: {len(distinct_ips)}")


def hash_idx(ip, size):
    return zlib.crc32(str(ip).encode()) % size


for size in [256, 512, 1024, 2048]:
    buckets = {}
    for ip in distinct_ips:
        idx = hash_idx(ip, size)
        buckets[idx] = buckets.get(idx, 0) + 1
    collided_ips = sum(c for c in buckets.values() if c > 1)
    collision_rate = collided_ips / len(distinct_ips) * 100
    print(f"register width={size}: {len(buckets)} distinct slots used, "
          f"{collision_rate:.2f}% of IPs share a slot with another IP")
