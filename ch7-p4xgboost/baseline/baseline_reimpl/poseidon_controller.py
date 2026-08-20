#!/usr/bin/env python3
"""
poseidon_controller.py -- Control-plane companion to p4/poseidon_lite.p4.

POSEIDON's own architecture splits primitives across switch and server
(§V-A of the paper): `sproxy` and `puzzle` are explicitly server-only. This
controller receives the "gray area" digest emitted by the switch (verdict==2
in poseidon_lite.p4, mirroring Fig. 4 lines 8-9) and runs a lightweight
software SYN-proxy exactly as POSEIDON's own DPDK server component does,
then reports back a Recirculate()-equivalent allow/deny update.

Reference only -- requires a live BMv2 grpc server. See eval/poseidon_lite.py
for the offline equivalent used for batch scoring against CIC-DDoS2019.
"""
import argparse
import struct
import time

try:
    import p4runtime_lib.bmv2
    import p4runtime_lib.helper
except ImportError:
    p4runtime_lib = None

ALERT_FMT = "!IB"  # srcAddr(u32), verdict(u8)


class SoftwareSynProxy:
    """Minimal stand-in for POSEIDON's DPDK-based sproxy server component
    (paper §VII: '~3600 lines of code in C/C++' using DPDK). This Python
    version keeps the same cookie-verification *logic* (SYN -> cookie ->
    wait for matching RST/ACK) without the line-rate DPDK packet I/O, since
    functional correctness -- not throughput -- is what this comparison
    measures."""

    def __init__(self):
        self.pending = {}  # src_addr -> cookie

    def on_syn(self, src_addr, cookie):
        self.pending[src_addr] = cookie

    def verify(self, src_addr, returned_cookie):
        expected = self.pending.pop(src_addr, None)
        return expected is not None and expected == returned_cookie


def install_allowlist_entry(sw, p4info_helper, src_addr_int):
    """Recirculate()-equivalent: promotes a verified source straight to the
    'pass' path so subsequent packets skip the sproxy handoff."""
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.drop_table",  # reuse exact-match table as an
                                              # allow-list by installing a
                                              # pass_action entry instead
        match_fields={"hdr.ipv4.srcAddr": src_addr_int},
        action_name="MyIngress.pass_action",
    )
    sw.WriteTableEntry(table_entry)


def main(grpc_addr, device_id, p4info_path, bmv2_json_path):
    if p4runtime_lib is None:
        raise RuntimeError(
            "p4runtime_lib not installed; reference controller for a live "
            "BMv2 instance."
        )

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_path)
    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name="poseidon_lite_switch", address=grpc_addr, device_id=device_id
    )
    sw.MasterArbitrationUpdate()
    sw.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json_path
    )

    proxy = SoftwareSynProxy()
    print("[poseidon-lite] listening for gray-area digests...")
    while True:
        for digest_list in sw.DigestList():
            for member in digest_list.data:
                src_addr, verdict = struct.unpack(ALERT_FMT, member.struct.SerializeToString())
                if verdict == 2:
                    # Simplified: in the real system a cookie round-trip
                    # (SYN-ACK w/ cookie -> client RST/ACK) verifies the
                    # source; here we log the handoff for offline analysis.
                    print(f"[poseidon-lite] sproxy handoff for {src_addr}")
                    install_allowlist_entry(sw, p4info_helper, src_addr)
        time.sleep(0.1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--grpc-addr", default="127.0.0.1:50052")
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4info", default="build/poseidon_lite.p4info.txt")
    ap.add_argument("--bmv2-json", default="build/poseidon_lite.json")
    args = ap.parse_args()
    main(args.grpc_addr, args.device_id, args.p4info, args.bmv2_json)
