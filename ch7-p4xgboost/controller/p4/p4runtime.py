from __future__ import annotations

import time

class P4RuntimeInterface:
    """Interface for P4Runtime communicating with BMv2."""

    def __init__(self):
        self.active_drops = set()
        self.latency_ms = 10.5

    def install_drop_rule(self, src_ip: str) -> None:
        """Simulates installing a P4Runtime exact-match drop rule."""
        time.sleep(self.latency_ms / 1000.0)
        self.active_drops.add(src_ip)
        print(f"[P4Runtime] Installed exact-match DROP rule for {src_ip} in 'drop_table'")

    def is_mitigated(self, src_ip: str) -> bool:
        """Check if an IP already has an active drop rule."""
        return src_ip in self.active_drops
