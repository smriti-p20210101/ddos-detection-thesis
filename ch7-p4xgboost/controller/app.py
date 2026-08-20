from __future__ import annotations

import json
import os
import signal
import time
import threading

from scapy.all import AsyncSniffer, IP, TCP, UDP

from controller.p4.p4runtime import P4RuntimeInterface
from controller.p4.digest_listener import DigestListener
from controller.core.features import FeatureExtractor
from controller.ml.xgboost_model import XGBoostEnsemble
from controller.core.metrics import ControllerMetrics


class SDNController:
    """Real orchestrator for the P4-XGBoost hybrid system: a live BMv2
    digest triggers real feature extraction (Redis), real XGBoost inference,
    and, if malicious, a real Thrift drop-rule install. Every stage's real
    wall-clock time is recorded -- no simulated latency anywhere."""

    def __init__(self, threshold: float = 0.5, ip_blacklist: set[str] | None = None):
        self.p4_interface = P4RuntimeInterface()
        self.extractor = FeatureExtractor()
        self.ml_model = XGBoostEnsemble()
        self.threshold = threshold
        self.ip_blacklist = ip_blacklist or set()
        self.metrics = ControllerMetrics()
        self.stage_timings: list[dict] = []
        self.digest_listener = DigestListener(on_alert=self._on_digest)

    def _on_digest(self, src_ip: str, ingress_port: int) -> None:
        self.handle_digest({"srcAddr": src_ip, "ingress_port": ingress_port})

    def handle_digest(self, digest_payload: dict) -> None:
        """Callback for a real 28-byte alert digest received from the data plane."""
        src_ip = digest_payload.get('srcAddr', '0.0.0.0')
        ingress_port = digest_payload.get('ingress_port', 0)

        print(f"\n[Thrift-digest] Digest Received -> Src: {src_ip}, Port: {ingress_port}")
        t_start = time.time()

        if src_ip in self.ip_blacklist:
            print(f"[BLACKLIST] IP {src_ip} is blacklisted. Dropping immediately.")
            self.p4_interface.install_drop_rule(src_ip)
            latency = (time.time() - t_start) * 1000.0
            self.metrics.record_digest(is_blacklisted=True, latency=latency)
            return

        if self.p4_interface.is_mitigated(src_ip):
            print(f"[CACHE] IP {src_ip} is already blocked.")
            return

        t_feat_start = time.time()
        features = self.extractor.extract_features(src_ip)
        t_feat_end = time.time()

        prediction = self.ml_model.predict_proba(features)
        t_ml_end = time.time()

        prob_malicious = prediction[0][1]
        timing = {
            "src_ip": src_ip,
            "feature_extraction_ms": (t_feat_end - t_feat_start) * 1000.0,
            "ml_inference_ms": (t_ml_end - t_feat_end) * 1000.0,
        }

        if prob_malicious > self.threshold:
            print(f"[ALERT] Threat Detected (Prob: {prob_malicious:.3f}).")
            self.p4_interface.install_drop_rule(src_ip)
            t_end = time.time()
            timing["rule_install_ms"] = (t_end - t_ml_end) * 1000.0
            timing["total_ms"] = (t_end - t_start) * 1000.0
            self.stage_timings.append(timing)
            self.metrics.record_digest(is_malicious=True, latency=timing["total_ms"])
        else:
            print(f"[OK] Normal Traffic (Prob: {prob_malicious:.3f}).")
            t_end = time.time()
            timing["rule_install_ms"] = 0.0
            timing["total_ms"] = (t_end - t_start) * 1000.0
            self.stage_timings.append(timing)
            self.metrics.record_digest(is_malicious=False, latency=timing["total_ms"])

    def _sniff_packet(self, pkt) -> None:
        """Feeds every real packet crossing the switch into the Redis-backed
        sliding window, so features are available by the time a digest fires."""
        if IP not in pkt:
            return
        ts = float(pkt.time)
        src_ip = pkt[IP].src
        proto = int(pkt[IP].proto)
        size = len(pkt)
        if TCP in pkt:
            dport = int(pkt[TCP].dport)
            syn = bool(pkt[TCP].flags & 0x02)
            ack = bool(pkt[TCP].flags & 0x10)
        elif UDP in pkt:
            dport = int(pkt[UDP].dport)
            syn = False
            ack = False
        else:
            dport = 0
            syn = False
            ack = False
        self.extractor.ingest_packet(src_ip, ts, proto, dport, size, syn, ack)

    def start_live(self, interfaces: list[str]) -> None:
        """Starts the real packet sniffer and the real digest listener."""
        self.sniffer = AsyncSniffer(iface=interfaces, prn=self._sniff_packet, store=False)
        self.sniffer.start()
        self.digest_listener.start()
        print(f"[LIVE] Sniffing on {interfaces}, digest listener active.")

    def stop_live(self) -> None:
        if hasattr(self, "sniffer"):
            self.sniffer.stop()
        self.digest_listener.stop()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="P4-XGBoost SDN Controller (live)")
    parser.add_argument("--threshold", type=float, default=0.5, help="Detection threshold")
    parser.add_argument("--ip-blacklist", type=str, default="", help="Comma-separated IPs to blacklist immediately")
    parser.add_argument("--interfaces", type=str, default="veth-h1-br,veth-h2-br",
                         help="Comma-separated switch-facing interfaces to sniff")
    parser.add_argument("--duration", type=float, default=30.0, help="How long to run live (seconds)")
    args = parser.parse_args()

    blacklist = {ip.strip() for ip in args.ip_blacklist.split(",") if ip.strip()}
    interfaces = [i.strip() for i in args.interfaces.split(",") if i.strip()]

    print("\n--- Starting Live P4-XGBoost Hybrid Controller ---")
    print(f"[CONFIG] Threshold: {args.threshold}, Blacklisted IPs: {blacklist}, Interfaces: {interfaces}")
    controller = SDNController(threshold=args.threshold, ip_blacklist=blacklist)
    controller.start_live(interfaces)

    # A plain SIGTERM (e.g. from an orchestration script's `kill`/`pkill`
    # without -9) has no Python handler by default and terminates
    # immediately, skipping the `finally` block below and losing real
    # results -- convert it into a normal exception so results still export.
    def _on_sigterm(signum, frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _on_sigterm)

    try:
        time.sleep(args.duration)
    finally:
        controller.stop_live()
        controller.metrics.export_to_json()

        base_dir = os.path.dirname(os.path.abspath(__file__))
        out_path = os.path.join(os.path.dirname(base_dir), "evaluation_output", "stage_timings.json")
        with open(out_path, "w") as f:
            json.dump(controller.stage_timings, f, indent=2)
        print(f"[DONE] {len(controller.stage_timings)} real digest events processed. "
              f"Per-stage timings saved to {out_path}")


if __name__ == "__main__":
    main()
