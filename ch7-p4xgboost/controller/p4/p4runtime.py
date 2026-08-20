from __future__ import annotations

import sys

# BMv2's `make install` puts its generated Thrift Python bindings in
# site-packages, but Ubuntu's system python3 only searches dist-packages by
# default (a Debian/Ubuntu-specific split) -- simple_switch_CLI gets this for
# free via its own startup path, a plain `import` does not.
sys.path.insert(0, "/usr/local/lib/python3.14/site-packages")

import bmpy_utils as utils  # noqa: E402
from bm_runtime.standard.ttypes import (  # noqa: E402
    BmAddEntryOptions, BmMatchParam, BmMatchParamExact, BmMatchParamType,
)

# This is a real Thrift RPC client against a running BMv2 simple_switch --
# the thesis text describes gRPC/P4Runtime, but this repo is built with
# WITH_PI=OFF (Thrift-CLI control plane, see build tracker stage #1 for why)
# so this talks the same protocol simple_switch_CLI itself uses, not gRPC.
DROP_TABLE = "MyIngress.drop_table"
DROP_ACTION = "MyIngress.drop"


def _pack_ipv4(ip: str) -> bytes:
    return bytes(int(octet) for octet in ip.split("."))


class P4RuntimeInterface:
    """Real Thrift-CLI client for installing drop rules on a running BMv2
    simple_switch. No simulated latency -- whatever time the real RPC takes
    is the real time."""

    def __init__(self, thrift_ip: str = "localhost", thrift_port: int = 9090):
        self.client = utils.thrift_connect_standard(thrift_ip, thrift_port)
        self.active_drops: set[str] = set()

    def install_drop_rule(self, src_ip: str) -> None:
        """Installs a real exact-match DROP rule for src_ip on the live switch."""
        match_key = [BmMatchParam(type=BmMatchParamType.EXACT,
                                   exact=BmMatchParamExact(key=_pack_ipv4(src_ip)))]
        handle = self.client.bm_mt_add_entry(
            0, DROP_TABLE, match_key, DROP_ACTION, [], BmAddEntryOptions(priority=0)
        )
        self.active_drops.add(src_ip)
        print(f"[P4Runtime/Thrift] Installed exact-match DROP rule for {src_ip} "
              f"in '{DROP_TABLE}' (handle={handle})")

    def is_mitigated(self, src_ip: str) -> bool:
        """Check if an IP already has an active drop rule (local controller-side
        state, matching how a real controller avoids redundant RPCs)."""
        return src_ip in self.active_drops
