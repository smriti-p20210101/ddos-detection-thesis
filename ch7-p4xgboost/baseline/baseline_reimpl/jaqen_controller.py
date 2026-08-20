#!/usr/bin/env python3
"""
jaqen_controller.py -- Control-plane companion to p4/jaqen_lite.p4.

Re-creates Jaqen's Query(proto, func, mode, freq) detection API (paper
Figure 4: UDPFlood() / DNSFlood() pseudocode) as a P4Runtime digest listener.
Written against the standard p4lang/tutorials P4Runtime helper pattern
(`p4runtime_lib`), which you already have if you've followed the BMv2
tutorials used elsewhere in this thesis's testbed. Requires a live BMv2
switch + grpc server to run; it is not exercised in this repo's automated
tests (see eval/jaqen_lite.py for the offline equivalent used for batch
scoring against CIC-DDoS2019).

Reference only -- adapt device_id / grpc_addr / p4info paths to your setup.
"""
import argparse
import time
import struct

try:
    import p4runtime_lib.bmv2
    import p4runtime_lib.helper
except ImportError:
    p4runtime_lib = None  # allows this file to be imported for documentation
                            # purposes without the p4runtime_lib dependency


ALERT_FMT = "!IB I"  # srcAddr(u32), attack_type(u8), metric_value(u32) -- must
                      # match the `jaqen_alert_t` digest struct field order


def decode_alert(digest_data: bytes):
    src_addr, attack_type, metric_value = struct.unpack(ALERT_FMT, digest_data)
    return {
        "src_addr": src_addr,
        "attack_type": "syn_asymmetry" if attack_type == 1 else "udp_heavy_hitter",
        "metric_value": metric_value,
    }


def install_drop_rule(sw, p4info_helper, src_addr_int):
    """Mirrors Jaqen's on-demand mitigation deployment: only block once the
    always-on detector has fired, keeping the drop_table sparse."""
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.drop_table",
        match_fields={"hdr.ipv4.srcAddr": src_addr_int},
        action_name="MyIngress.drop_action",
    )
    sw.WriteTableEntry(table_entry)


def main(grpc_addr, device_id, p4info_path, bmv2_json_path):
    if p4runtime_lib is None:
        raise RuntimeError(
            "p4runtime_lib not installed; this is a reference controller "
            "meant to run against a live BMv2 instance in your Mininet "
            "testbed, following the same p4runtime_lib pattern used for "
            "the P4-XGBoost controller in Chapter 7."
        )

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_path)
    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name="jaqen_lite_switch", address=grpc_addr, device_id=device_id
    )
    sw.MasterArbitrationUpdate()
    sw.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json_path
    )

    print("[jaqen-lite] listening for digests...")
    seen_sources = set()
    while True:
        for digest_list in sw.DigestList():
            for member in digest_list.data:
                alert = decode_alert(member.struct.SerializeToString())
                seen_sources.add(alert["src_addr"])
                print(f"[jaqen-lite] ALERT {alert}")
                install_drop_rule(sw, p4info_helper, alert["src_addr"])
        time.sleep(0.1)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--grpc-addr", default="127.0.0.1:50051")
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4info", default="build/jaqen_lite.p4info.txt")
    ap.add_argument("--bmv2-json", default="build/jaqen_lite.json")
    args = ap.parse_args()
    main(args.grpc_addr, args.device_id, args.p4info, args.bmv2_json)
