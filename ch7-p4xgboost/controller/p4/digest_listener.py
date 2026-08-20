from __future__ import annotations

import socket
import struct
import sys
import threading
from typing import Callable

sys.path.insert(0, "/usr/local/lib/python3.14/site-packages")

import pynng  # noqa: E402
import bmpy_utils as utils  # noqa: E402

# Real BMv2 learn-notification wire format, reverse-engineered from
# behavioral-model's src/bm_sim/learning.cpp / include/bm/bm_sim/learning.h
# (LearnEngineIface::msg_hdr_t, static_assert'd to 32 bytes) and verified
# byte-for-byte against a live digest during stage #14 testing: the 32-byte
# header is host byte order (little-endian on x86, hence "<"), but the
# per-sample payload bytes are raw P4 header field bytes, i.e. network byte
# order, since they mirror the wire format directly.
HDR_FMT = "<4sQIiQI"
HDR_LEN = struct.calcsize(HDR_FMT)
assert HDR_LEN == 32
SAMPLE_LEN = 6  # alert_digest_t: 4-byte srcAddr + 9-bit ingress_port padded to 2 bytes


def _decode_sample(raw: bytes) -> tuple[str, int]:
    src_addr = socket.inet_ntoa(raw[0:4])
    ingress_port = struct.unpack("!H", raw[4:6])[0]
    return src_addr, ingress_port


class DigestListener:
    """Subscribes to BMv2's real nanomsg learn-notification socket and, for
    each real alert_digest_t sample, invokes on_alert(src_ip, ingress_port).
    Sends the real Thrift bm_learning_ack_buffer acknowledgment back to the
    switch after processing each buffer, matching real BMv2 control-plane
    behavior (unacknowledged buffers get retransmitted)."""

    def __init__(self, on_alert: Callable[[str, int], None],
                 notifications_addr: str = "ipc:///tmp/bmv2-0-notifications.ipc",
                 thrift_ip: str = "localhost", thrift_port: int = 9090):
        self.on_alert = on_alert
        self.notifications_addr = notifications_addr
        self.thrift_client = utils.thrift_connect_standard(thrift_ip, thrift_port)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _run(self) -> None:
        with pynng.Sub0(dial=self.notifications_addr) as sock:
            sock.subscribe(b"")
            sock.recv_timeout = 500
            while not self._stop.is_set():
                try:
                    msg = sock.recv()
                except pynng.exceptions.Timeout:
                    continue
                if len(msg) < HDR_LEN:
                    continue
                sub_topic, switch_id, cxt_id, list_id, buffer_id, num_samples = \
                    struct.unpack(HDR_FMT, msg[:HDR_LEN])
                if sub_topic != b"LEA|":
                    continue
                payload = msg[HDR_LEN:]
                for i in range(num_samples):
                    start = i * SAMPLE_LEN
                    sample = payload[start:start + SAMPLE_LEN]
                    if len(sample) < SAMPLE_LEN:
                        break
                    src_ip, ingress_port = _decode_sample(sample)
                    self.on_alert(src_ip, ingress_port)
                self.thrift_client.bm_learning_ack_buffer(cxt_id, list_id, buffer_id)
