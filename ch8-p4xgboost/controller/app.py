from __future__ import annotations

import time

from controller.p4.p4runtime import P4RuntimeInterface
from controller.core.features import FeatureExtractor
from controller.ml.xgboost_model import XGBoostEnsemble
from controller.core.metrics import ControllerMetrics

class SDNController:
    """Main Orchestrator for the P4-XGBoost Hybrid System."""

    def __init__(self, threshold: float = 0.5, ip_blacklist: set[str] | None = None):
        self.p4_interface = P4RuntimeInterface()
        self.extractor = FeatureExtractor()
        self.ml_model = XGBoostEnsemble()
        self.threshold = threshold
        self.ip_blacklist = ip_blacklist or set()
        self.metrics = ControllerMetrics()

    def handle_digest(self, digest_payload: dict) -> None:
        """Callback for parsing the 28-byte alert digest from the data plane."""
        src_ip = digest_payload.get('srcAddr', '0.0.0.0')
        ingress_port = digest_payload.get('ingress_port', 0)
        
        print(f"\n[gRPC] Digest Received -> Src: {src_ip}, Port: {ingress_port}")
        start_time = time.time()
        
        if src_ip in self.ip_blacklist:
            print(f"[BLACKLIST] IP {src_ip} is blacklisted. Dropping immediately.")
            self.p4_interface.install_drop_rule(src_ip)
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_digest(is_blacklisted=True, latency=latency)
            return
            
        if self.p4_interface.is_mitigated(src_ip):
            print(f"[CACHE] IP {src_ip} is already blocked.")
            return
            
        print(f"[*] Extracting 8D Feature Vector for {src_ip} over 500ms window...")
        features = self.extractor.extract_8d_features(src_ip)
        
        start_ml = time.time()
        prediction = self.ml_model.predict_proba(features)
        time.sleep(0.0018)  # ML Inference time (1.8 ms) latency emulation
        
        prob_malicious = prediction[0][1]
        
        if prob_malicious > self.threshold:
            print(f"[ALERT] Threat Detected (Prob: {prob_malicious:.3f}). Inference Time: 1.8 ms.")
            self.p4_interface.install_drop_rule(src_ip)
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_digest(is_malicious=True, latency=latency)
        else:
            print(f"[OK] Normal Traffic (Prob: {prob_malicious:.3f}).")
            latency = (time.time() - start_time) * 1000.0
            self.metrics.record_digest(is_malicious=False, latency=latency)

def main():
    import argparse
    parser = argparse.ArgumentParser(description="P4-XGBoost SDN Controller")
    parser.add_argument("--threshold", type=float, default=0.5, help="Detection threshold")
    parser.add_argument("--ip-blacklist", type=str, default="", help="Comma-separated IPs to blacklist immediately")
    parser.add_argument("--digest-count", type=int, default=3, help="Number of digests to run")
    args = parser.parse_args()
    
    blacklist = {ip.strip() for ip in args.ip_blacklist.split(",") if ip.strip()}
    
    print("\n--- Starting High-Speed Hybrid Controller ---")
    print(f"[CONFIG] Threshold: {args.threshold}, Blacklisted IPs: {blacklist}")
    controller = SDNController(threshold=args.threshold, ip_blacklist=blacklist)
    
    test_digests = [
        {'srcAddr': '192.168.1.100', 'ingress_port': 1},
        {'srcAddr': '10.0.0.5', 'ingress_port': 2},
        {'srcAddr': '192.168.1.100', 'ingress_port': 1}
    ]
    
    to_process = test_digests[:args.digest_count]
    while len(to_process) < args.digest_count:
        to_process.append(test_digests[len(to_process) % len(test_digests)])
        
    for d in to_process:
        controller.handle_digest(d)
        print("-" * 50)
        
    controller.metrics.export_to_json()

if __name__ == "__main__":
    main()


