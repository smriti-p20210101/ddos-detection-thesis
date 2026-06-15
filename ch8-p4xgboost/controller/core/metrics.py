from __future__ import annotations

import json
import os

class ControllerMetrics:
    """Utility to track and export controller processing metrics."""

    def __init__(self):
        self.digests_processed = 0
        self.malicious_detected = 0
        self.benign_detected = 0
        self.blacklisted_count = 0
        self.latencies = []

    def record_digest(self, is_blacklisted: bool = False, is_malicious: bool = False, latency: float = 0.0):
        self.digests_processed += 1
        if is_blacklisted:
            self.blacklisted_count += 1
        elif is_malicious:
            self.malicious_detected += 1
        else:
            self.benign_detected += 1
        
        if latency > 0:
            self.latencies.append(latency)

    def export_to_json(self) -> None:
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        output_dir = os.path.join(base_dir, "evaluation_output")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "controller_metrics.json")
        
        avg_latency = sum(self.latencies) / len(self.latencies) if self.latencies else 0.0
        
        metrics_data = {
            "digests_processed": self.digests_processed,
            "malicious_detected": self.malicious_detected,
            "benign_detected": self.benign_detected,
            "blacklisted_count": self.blacklisted_count,
            "average_mitigation_latency_ms": avg_latency,
            "total_mitigated": self.malicious_detected + self.blacklisted_count
        }
        
        with open(output_path, "w") as f:
            json.dump(metrics_data, f, indent=4)
        print(f"[METRICS] Exported controller metrics to {output_path}")
