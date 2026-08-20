from __future__ import annotations

import statistics
import time

import redis


class FeatureExtractor:
    """Computes the 10D feature vector from real packets over a sliding window,
    backed by Redis for per-source-IP state (matching the paper's described
    500ms selective-mirroring window).

    Feature order: [pkt_rate, byte_rate, duration, proto_var, port_div,
    size_var, tcp_flags, inter_arrival, syn_noack_ratio, ack_ratio]

    syn_noack_ratio and ack_ratio were added after a real evaluation found
    the model conflated real TCP handshake SYNs with attack SYN-flood
    packets via the single generic tcp_flags (SYN fraction) feature;
    isolating SYN-without-ACK specifically (already computed for real
    attack-type ground-truth labeling in controller/ml/train_model.py, but
    not previously exposed to the model) measurably improved accuracy at
    the SAME 0.5s window -- no detection-latency cost, unlike widening the
    window.
    """

    WINDOW_SECONDS = 0.5

    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379, redis_db: int = 0):
        self.redis = redis.Redis(host=redis_host, port=redis_port, db=redis_db, decode_responses=True)

    def _key(self, src_ip: str) -> str:
        return f"pkt_window:{src_ip}"

    def ingest_packet(self, src_ip: str, timestamp: float, protocol: int,
                       dst_port: int, size: int, tcp_syn: bool, tcp_ack: bool = False) -> None:
        """Records one packet from src_ip into its Redis sliding window."""
        key = self._key(src_ip)
        # member must be unique per packet even if two packets share a timestamp,
        # so pack a disambiguating counter via ZADD's own float score precision
        # is not reliable for that -- append a monotonically increasing suffix instead.
        member = (f"{timestamp!r}|{protocol}|{dst_port}|{size}|{int(tcp_syn)}|{int(tcp_ack)}|"
                  f"{self.redis.incr(f'{key}:seq')}")
        pipe = self.redis.pipeline()
        pipe.zadd(key, {member: timestamp})
        pipe.zremrangebyscore(key, 0, timestamp - self.WINDOW_SECONDS)
        pipe.expire(key, 5)
        pipe.execute()

    def extract_features(self, src_ip: str, now: float | None = None) -> list[float]:
        """Reads the current window for src_ip from Redis and computes the 10D vector.
        Returns an all-zero vector if no packets are in the window (nothing observed)."""
        now = now if now is not None else time.time()
        key = self._key(src_ip)
        self.redis.zremrangebyscore(key, 0, now - self.WINDOW_SECONDS)
        members = self.redis.zrange(key, 0, -1, withscores=True)

        if not members:
            return [0.0] * 10

        records = []
        for member, score in members:
            parts = member.split("|")
            ts_str, proto_str, dport_str, size_str, syn_str = parts[:5]
            ack_str = parts[5] if len(parts) > 6 else "0"  # tolerate pre-upgrade Redis entries without ack
            records.append({
                "ts": score,
                "protocol": int(proto_str),
                "dst_port": int(dport_str),
                "size": int(size_str),
                "syn": bool(int(syn_str)),
                "ack": bool(int(ack_str)),
            })
        return compute_features(records, self.WINDOW_SECONDS)


def compute_features(records: list[dict], window_seconds: float) -> list[float]:
    """Pure function computing the 10D vector from a list of packet records
    ({ts, protocol, dst_port, size, syn, ack}). Shared by the live Redis-backed
    path above and controller/ml/train_model.py's fast in-memory batch path
    (streaming millions of packets through Redis round-trips for offline
    training would be impractically slow, so batch training keeps the same
    window accounting in memory instead -- same math, different backing
    store, documented here rather than silently duplicated).
    """
    if not records:
        return [0.0] * 10

    records = sorted(records, key=lambda r: r["ts"])
    count = len(records)
    timestamps = [r["ts"] for r in records]
    sizes = [r["size"] for r in records]
    protocols = [r["protocol"] for r in records]
    dst_ports = {r["dst_port"] for r in records}
    syn_count = sum(1 for r in records if r["syn"])
    ack_count = sum(1 for r in records if r.get("ack"))
    syn_noack_count = sum(1 for r in records if r["syn"] and not r.get("ack"))

    span = timestamps[-1] - timestamps[0]
    duration = span if span > 0 else window_seconds
    total_bytes = sum(sizes)

    pkt_rate = count / window_seconds
    byte_rate = total_bytes / window_seconds
    proto_var = statistics.pvariance(protocols) if count > 1 else 0.0
    port_div = float(len(dst_ports))
    size_var = statistics.pvariance(sizes) if count > 1 else 0.0
    tcp_flags = syn_count / count
    if count > 1:
        gaps = [timestamps[i] - timestamps[i - 1] for i in range(1, count)]
        inter_arrival = sum(gaps) / len(gaps)
    else:
        inter_arrival = 0.0
    syn_noack_ratio = syn_noack_count / count
    ack_ratio = ack_count / count

    return [pkt_rate, byte_rate, duration, proto_var, port_div, size_var, tcp_flags, inter_arrival,
            syn_noack_ratio, ack_ratio]
