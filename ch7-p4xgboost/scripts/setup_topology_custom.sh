#!/bin/bash
# Same real topology as setup_topology.sh, parametrized to load an
# arbitrary compiled BMv2 JSON (used by the digest-payload-size ablation
# to swap between the 3 real compiled variants without duplicating the
# whole topology script). Usage: setup_topology_custom.sh /path/to/x.json
set -e

SWITCH_JSON="$1"
if [ -z "$SWITCH_JSON" ]; then
  echo "usage: $0 /path/to/compiled_switch.json" >&2
  exit 1
fi

echo "[topology] tearing down any previous topology..."
sudo ip netns del h1 2>/dev/null || true
sudo ip netns del h2 2>/dev/null || true
sudo ip link del veth-h1-br 2>/dev/null || true
sudo ip link del veth-h2-br 2>/dev/null || true
sudo pkill simple_switch 2>/dev/null || true
sleep 1

echo "[topology] creating host namespaces..."
sudo ip netns add h1
sudo ip netns add h2

echo "[topology] creating veth pairs..."
sudo ip link add veth-h1 type veth peer name veth-h1-br
sudo ip link add veth-h2 type veth peer name veth-h2-br

sudo ip link set veth-h1 netns h1
sudo ip link set veth-h2 netns h2

sudo ip netns exec h1 ip addr add 10.0.1.1/24 dev veth-h1
sudo ip netns exec h1 ip link set veth-h1 up
sudo ip netns exec h1 ip link set lo up

sudo ip netns exec h2 ip addr add 10.0.1.2/24 dev veth-h2
sudo ip netns exec h2 ip link set veth-h2 up
sudo ip netns exec h2 ip link set lo up

sudo ip link set veth-h1-br up
sudo ip link set veth-h2-br up

echo "[topology] starting simple_switch with $SWITCH_JSON ..."
sudo setsid nohup simple_switch --log-console \
  -i 0@veth-h1-br -i 1@veth-h2-br --thrift-port 9090 \
  "$SWITCH_JSON" > /tmp/simple_switch.log 2>&1 < /dev/null &
disown
sleep 2

echo "[topology] populating ipv4_lpm forwarding table..."
simple_switch_CLI --thrift-port 9090 <<EOF
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.1.1/32 => 00:00:00:00:01:01 0
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.1.2/32 => 00:00:00:00:01:02 1
EOF

sudo ip netns exec h1 ip link set veth-h1 address 00:00:00:00:01:01
sudo ip netns exec h2 ip link set veth-h2 address 00:00:00:00:01:02
sudo ip netns exec h1 ip neigh add 10.0.1.2 lladdr 00:00:00:00:01:02 dev veth-h1
sudo ip netns exec h2 ip neigh add 10.0.1.1 lladdr 00:00:00:00:01:01 dev veth-h2

echo "[topology] done ($SWITCH_JSON loaded)."
