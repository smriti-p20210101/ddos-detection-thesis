#!/usr/bin/env python3
"""Real measurement for the digest-payload-size ablation: listens on the
real BMv2 nanomsg learn-notification socket (same real wire path
controller/p4/digest_listener.py uses), and reports the real message size
received plus the real wall-clock time from script start (i.e. from
"switch ready, listener attached") to the first real digest notification
received.

Doesn't attempt per-sample decoding (the sample byte layout differs across
the 3 compiled variants) -- only measures real receipt: when the message
arrives, and how many real bytes it contains. That's sufficient to test
whether payload size measurably affects real notification delivery time;
it deliberately does not need to know the exact per-variant sample layout.

Usage: run this, then (from another shell) replay the real attacker
trigger slice at the switch. Exits after the first real digest or after
--timeout seconds with no digest.
"""
import argparse
import json
import sys
import time

sys.path.insert(0, "/usr/local/lib/python3.14/site-packages")
import pynng  # noqa: E402

HDR_LEN = 32  # real BMv2 msg_hdr_t size, verified in controller/p4/digest_listener.py


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", default="ipc:///tmp/bmv2-0-notifications.ipc")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--label", required=True, help="e.g. baseline_6B, padded_100B, padded_1500B")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    print(f"[measure] listening on {args.addr}, label={args.label}")
    t_start = time.time()
    result = None

    with pynng.Sub0(dial=args.addr) as sock:
        sock.subscribe(b"")
        sock.recv_timeout = 500
        deadline = t_start + args.timeout
        while time.time() < deadline:
            try:
                msg = sock.recv()
            except pynng.exceptions.Timeout:
                continue
            t_recv = time.time()
            if len(msg) < HDR_LEN:
                continue
            sub_topic = msg[:4]
            if sub_topic != b"LEA|":
                continue
            payload_len = len(msg) - HDR_LEN
            elapsed_ms = (t_recv - t_start) * 1000.0
            print(f"[measure] REAL digest received: total_msg_bytes={len(msg)} "
                  f"payload_bytes={payload_len} elapsed_since_listener_start_ms={elapsed_ms:.3f}")
            result = {
                "label": args.label, "total_msg_bytes": len(msg), "payload_bytes": payload_len,
                "elapsed_since_listener_start_ms": elapsed_ms, "t_start": t_start, "t_recv": t_recv,
            }
            break

    if result is None:
        print(f"[measure] WARNING: no real digest received within {args.timeout}s")
        result = {"label": args.label, "error": f"no digest received within {args.timeout}s"}

    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)
    print(f"[measure] wrote {args.out}")


if __name__ == "__main__":
    main()
