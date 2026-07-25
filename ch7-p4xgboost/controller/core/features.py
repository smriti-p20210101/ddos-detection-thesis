from __future__ import annotations

import time

class FeatureExtractor:
    """Simulates extraction of the 8D feature vector via network state."""

    def __init__(self):
        self.extraction_delay_ms = 2.1
        
    def extract_8d_features(self, src_ip: str) -> list[float]:
        """
        Simulates selective mirroring stage (500ms temporary trace).
        Returns the extracted feature vector [pkt_rate, byte_rate, duration, proto_var, port_div, size_var, tcp_flags, inter_arrival]
        """
        time.sleep(self.extraction_delay_ms / 1000.0)
        
        # Hardcoded simulated features for demonstration
        if src_ip.startswith("10."):
            return [80, 15000, 2.5, 0.4, 2, 0.15, 0.2, 0.05]
        return [1200, 1500000, 0.5, 0.1, 1, 0.05, 0.8, 0.0001]
