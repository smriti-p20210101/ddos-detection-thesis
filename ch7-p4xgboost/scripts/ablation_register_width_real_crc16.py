#!/usr/bin/env python3
"""Real bit-exact CRC16 collision-rate ablation, replacing the crc32
approximation in scripts/ablation_register_width.py.

BMv2's real HashAlgorithm.crc16 (verified directly against BMv2 source,
~/build/behavioral-model/src/bm_sim/calculations.cpp, crc_custom_init<uint16_t>):
  poly=0x8005, init=0x0000, xorout=0x0000, refin=True, refout=True
  -- this is the standard CRC-16/ARC. crcmod's config
  mkCrcFun(0x18005, initCrc=0x0000, rev=True, xorOut=0x0000) was verified
  against the independent published CRC-16/ARC check value (0xBB3D for
  ASCII "123456789") before use here -- not just assumed correct.

Real input encoding: p4/p4_xgboost.p4's actual hash() call is
  hash(meta.flow_hash, HashAlgorithm.crc16, (bit<10>)0, {hdr.ipv4.srcAddr}, (bit<10>)1023)
i.e. the hash input is the RAW 4-byte big-endian on-wire IPv4 address, not
a decimal-dotted string -- the original ablation's
zlib.crc32(str(ip).encode()) used the string representation instead. Both
differences (crc32-vs-crc16, string-vs-raw-bytes) are corrected here.
"""
import socket
import struct

import crcmod
import pandas as pd

# Verified against the published CRC-16/ARC check value before use (see module docstring).
_crc16_arc = crcmod.mkCrcFun(0x18005, initCrc=0x0000, rev=True, xorOut=0x0000)


def real_crc16_index(ip_str: str, size: int) -> int:
    raw = socket.inet_aton(ip_str)  # real 4-byte big-endian on-wire representation
    return _crc16_arc(raw) % size


def approx_crc32_index(ip_str: str, size: int) -> int:
    import zlib
    return zlib.crc32(str(ip_str).encode()) % size


def main():
    df = pd.read_csv("evaluation_output/extracted_features.csv")
    distinct_ips = df["src_ip"].unique()
    print(f"real distinct source IPs in dataset: {len(distinct_ips)}")

    for size in [256, 512, 1024, 2048]:
        buckets_real, buckets_approx = {}, {}
        for ip in distinct_ips:
            idx_real = real_crc16_index(ip, size)
            idx_approx = approx_crc32_index(ip, size)
            buckets_real[idx_real] = buckets_real.get(idx_real, 0) + 1
            buckets_approx[idx_approx] = buckets_approx.get(idx_approx, 0) + 1

        collided_real = sum(c for c in buckets_real.values() if c > 1)
        collided_approx = sum(c for c in buckets_approx.values() if c > 1)
        rate_real = collided_real / len(distinct_ips) * 100
        rate_approx = collided_approx / len(distinct_ips) * 100
        print(f"width={size:>5}: REAL bit-exact CRC16(raw bytes)={rate_real:.2f}%   "
              f"crc32-approx(string, prior ablation)={rate_approx:.2f}%   "
              f"delta={rate_real - rate_approx:+.2f}pp")


if __name__ == "__main__":
    main()
