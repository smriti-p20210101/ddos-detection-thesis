#!/usr/bin/env python3
"""
flowlens_controller.py -- Control-plane companion to p4/flowlens_lite.p4.

Re-creates FlowLens's "collector" + "classifier" components (paper §III):
the collector fetches the 10-bin flow marker from the switch register grid
each collection window, and the classifier scores it. FlowLens's own paper
uses XGBoost (covert channels), Multinomial Naive-Bayes (website
fingerprinting), or Random Forest (botnet chatter) depending on use case; for
this DDoS re-purposing we use Random Forest, since P2P-botnet chatter
detection (packet-length + inter-arrival based) is the closest of the three
original use cases to flooding-style anomaly detection.

Reference only -- requires a live BMv2 grpc server. See eval/flowlens_lite.py
for the offline equivalent (same feature construction + RandomForestClassifier)
used for batch scoring against CIC-DDoS2019, which is what actually produces
the numbers in results/table_7_6_functional.md.
"""
import argparse
import time

import joblib
import numpy as np

try:
    import p4runtime_lib.bmv2
    import p4runtime_lib.helper
except ImportError:
    p4runtime_lib = None

NUM_BINS = 10


def read_flow_marker(sw, p4info_helper, flow_offset, num_bins=NUM_BINS):
    """Reads the num_bins register cells for one flow_offset row of the
    marker_grid register array (paper §III: 'the collector fetches the
    resulting flow markers from the data plane')."""
    bins = []
    for b in range(num_bins):
        idx = flow_offset * num_bins + b
        entry = sw.ReadRegister("MyIngress.marker_grid", idx)
        bins.append(entry)
    return np.array(bins, dtype=np.float64)


def main(grpc_addr, device_id, p4info_path, bmv2_json_path, model_path, poll_hz):
    if p4runtime_lib is None:
        raise RuntimeError(
            "p4runtime_lib not installed; reference controller for a live "
            "BMv2 instance."
        )

    clf = joblib.load(model_path)  # trained offline via eval/flowlens_lite.py

    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_path)
    sw = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name="flowlens_lite_switch", address=grpc_addr, device_id=device_id
    )
    sw.MasterArbitrationUpdate()
    sw.SetForwardingPipelineConfig(
        p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_json_path
    )

    print("[flowlens-lite] polling flow markers...")
    while True:
        # In the real system the flow table (flow_offset -> src_ip mapping)
        # is walked here; simplified to a fixed scan window for this
        # reference implementation.
        for flow_offset in range(1024):
            marker = read_flow_marker(sw, p4info_helper, flow_offset)
            if marker.sum() == 0:
                continue
            pred = clf.predict(marker.reshape(1, -1))[0]
            if pred == 1:
                print(f"[flowlens-lite] flow_offset={flow_offset} classified ATTACK")
        time.sleep(1.0 / poll_hz)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--grpc-addr", default="127.0.0.1:50053")
    ap.add_argument("--device-id", type=int, default=0)
    ap.add_argument("--p4info", default="build/flowlens_lite.p4info.txt")
    ap.add_argument("--bmv2-json", default="build/flowlens_lite.json")
    ap.add_argument("--model", default="eval/flowlens_rf_model.joblib")
    ap.add_argument("--poll-hz", type=float, default=2.0)
    args = ap.parse_args()
    main(args.grpc_addr, args.device_id, args.p4info, args.bmv2_json, args.model, args.poll_hz)
