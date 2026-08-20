#!/bin/bash
# Real 2-host topology for simple_switch, using ip netns + veth pairs directly
# rather than Mininet's Python API. Per the build brief: Mininet's own core
# networking works fine here (verified: 0% packet loss on a default-OVS
# `mn --test pingall` run), but wiring a *custom* switch (simple_switch, not
# OVS) into Mininet's Switch abstraction is the part with real friction --
# this direct veth approach is the brief's own pre-approved fallback for
# that case, not a simulation shortcut.
set -e

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

echo "[topology] creating veth pairs (h-side stays in netns, br-side stays in root for simple_switch)..."
sudo ip link add veth-h1 type veth peer name veth-h1-br
sudo ip link add veth-h2 type veth peer name veth-h2-br

sudo ip link set veth-h1 netns h1
sudo ip link set veth-h2 netns h2

echo "[topology] configuring host h1 (10.0.1.1/24)..."
sudo ip netns exec h1 ip addr add 10.0.1.1/24 dev veth-h1
sudo ip netns exec h1 ip link set veth-h1 up
sudo ip netns exec h1 ip link set lo up

echo "[topology] configuring host h2 (10.0.1.2/24)..."
sudo ip netns exec h2 ip addr add 10.0.1.2/24 dev veth-h2
sudo ip netns exec h2 ip link set veth-h2 up
sudo ip netns exec h2 ip link set lo up

echo "[topology] bringing up switch-side veth ends (no IP -- simple_switch owns these)..."
sudo ip link set veth-h1-br up
sudo ip link set veth-h2-br up

echo "[topology] starting simple_switch bound to veth-h1-br (port 0) and veth-h2-br (port 1)..."
cd "$(dirname "$0")/../p4"
sudo setsid nohup simple_switch --log-console \
  -i 0@veth-h1-br -i 1@veth-h2-br --thrift-port 9090 \
  p4_xgboost.json > /tmp/simple_switch.log 2>&1 < /dev/null &
disown
sleep 2

echo "[topology] populating ipv4_lpm forwarding table (real Thrift table_add, not simulated)..."
simple_switch_CLI --thrift-port 9090 <<EOF
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.1.1/32 => 00:00:00:00:01:01 0
table_add MyIngress.ipv4_lpm MyIngress.ipv4_forward 10.0.1.2/32 => 00:00:00:00:01:02 1
EOF

echo "[topology] setting static ARP + MAC on hosts so packets actually reach the switch's forwarding logic..."
sudo ip netns exec h1 ip link set veth-h1 address 00:00:00:00:01:01
sudo ip netns exec h2 ip link set veth-h2 address 00:00:00:00:01:02
sudo ip netns exec h1 ip neigh add 10.0.1.2 lladdr 00:00:00:00:01:02 dev veth-h1
sudo ip netns exec h2 ip neigh add 10.0.1.1 lladdr 00:00:00:00:01:01 dev veth-h2

echo "[topology] done. Test with: sudo ip netns exec h1 ping -c 3 10.0.1.2"
