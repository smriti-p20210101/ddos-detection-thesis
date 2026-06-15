#!/usr/bin/env python3
"""
deep_tree.py

Deep-Tree Topology — 3-layer hierarchy
1 Core + 2 Aggregation + 4 Edge switches + 8 hosts
Section 5.2, paper Table 7 'Deep-Tree (Worst Scaling)'.

Used to measure how network diameter affects gossip
convergence. The hierarchical structure requires gossip
messages to travel through multiple layers.

Results (paper Table 7):
  25  switches: 80% convergence 200 ms, max CPU 42%
  50  switches: 80% convergence 260 ms, max CPU 48%
  100 switches: 80% convergence 340 ms, max CPU 55%
  150 switches: 80% convergence 420 ms, max CPU 60%
  F1 score: 0.90 (constant across scale)

  h1,h2 -- edge1 --\
  h3,h4 -- edge2 -- agg1 --\
  h5,h6 -- edge3 --/         core
  h7,h8 -- edge4 -- agg2 --/

Reference:
  Smriti Smriti et al., ACM Journal, 2026, Section 5.2.
"""

from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from p4_mininet import P4Switch, P4Host
import argparse, os

THISDIR = os.path.dirname(os.path.realpath(__file__))
P4SRC   = os.path.join(THISDIR, '..', 'p4', 'gossip_detect.p4')


def build_topology(thrift_port_base=9090):
    """
    3-layer deep tree: 1 core, 2 aggregation, 4 edge, 8 hosts.
    Total: 7 switches (matches paper Table 8, Deep-Tree row).
    """
    net = Mininet(
        switch=P4Switch,
        host=P4Host,
        link=TCLink,
        controller=None
    )

    def add_sw(name, dev_id):
        return net.addSwitch(
            name,
            sw_path='simple_switch',
            json_path=P4SRC,
            thrift_port=thrift_port_base + dev_id - 1,
            device_id=dev_id
        )

    # ---- layer 0: core -----------------------------------------
    core = add_sw('core', 1)

    # ---- layer 1: aggregation ----------------------------------
    agg1 = add_sw('agg1', 2)
    agg2 = add_sw('agg2', 3)

    # ---- layer 2: edge -----------------------------------------
    edge1 = add_sw('edge1', 4)
    edge2 = add_sw('edge2', 5)
    edge3 = add_sw('edge3', 6)
    edge4 = add_sw('edge4', 7)

    # ---- hosts (2 per edge switch, paper Section 5.2) -----------
    host_id = 1
    for edge_sw in [edge1, edge2, edge3, edge4]:
        for _ in range(2):
            h = net.addHost(
                'h%d' % host_id,
                ip='10.0.%d.1/24' % host_id,
                mac='00:00:00:00:00:%02x' % host_id
            )
            net.addLink(h, edge_sw, bw=1000, delay='1ms')
            host_id += 1

    # Attacker on edge1
    atk = net.addHost(
        'atk',
        ip='10.0.99.1/24',
        mac='00:00:00:00:99:01'
    )
    net.addLink(atk, edge1, bw=10000, delay='0ms')

    # ---- inter-switch links ------------------------------------
    # Layer 2 → Layer 1
    net.addLink(edge1, agg1, bw=10000, delay='2ms')
    net.addLink(edge2, agg1, bw=10000, delay='2ms')
    net.addLink(edge3, agg2, bw=10000, delay='2ms')
    net.addLink(edge4, agg2, bw=10000, delay='2ms')

    # Layer 1 → Layer 0
    net.addLink(agg1, core, bw=10000, delay='2ms')
    net.addLink(agg2, core, bw=10000, delay='2ms')

    return net


def run(args):
    setLogLevel('info')
    net = build_topology(args.thrift_port)
    net.start()

    info('\n*** Deep-Tree topology started\n')
    info('    Layers : core (1) → agg (2) → edge (4)\n')
    info('    Switches: 7 total\n')
    info('    Hosts   : 8 benign + 1 attacker\n')

    from controller.controller import populate_tables
    populate_tables(net, topology='deep_tree')

    if args.cli:
        from mininet.cli import CLI
        CLI(net)

    net.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Deep-Tree Topology (Chapter 5)')
    parser.add_argument('--thrift-port', type=int, default=9090)
    parser.add_argument('--cli', action='store_true')
    run(parser.parse_args())
