#!/usr/bin/env python3
"""
spine_leaf.py

Spine-Leaf Topology — 2 Spine + 3 Leaf switches (5 total)
Section 5.2, paper Table 7 'Spine-Leaf (Best Scaling)'.

Modern datacenter design; fully bipartite graph with many
redundant paths. Used to measure gossip performance when
many possible paths exist.

Results (paper Table 7):
  25  switches: 80% convergence 160 ms, max CPU 38%
  50  switches: 80% convergence 190 ms, max CPU 42%
  100 switches: 80% convergence 220 ms, max CPU 47%
  150 switches: 80% convergence 250 ms, max CPU 52%
  F1 score: 0.90 (constant across scale)

    h1--leaf1  leaf2--h3
          \   /
    spine1-X-spine2
          /   \
    h2--leaf3  (additional leaves for larger scale)

Reference:
  Smriti Smriti et al., ACM Journal, 2026, Section 5.2.
"""

from mininet.net import Mininet
from mininet.node import Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from p4_mininet import P4Switch, P4Host
import argparse, os

THISDIR = os.path.dirname(os.path.realpath(__file__))
P4SRC   = os.path.join(THISDIR, '..', 'p4', 'gossip_detect.p4')


def build_topology(n_spine=2, n_leaf=3, thrift_port_base=9090):
    """
    Build a spine-leaf topology.

    Args:
        n_spine: number of spine switches (paper uses 2)
        n_leaf : number of leaf switches  (paper uses 3)
    """
    net = Mininet(
        switch=P4Switch,
        host=P4Host,
        link=TCLink,
        controller=None
    )

    spines = []
    leaves = []
    device_id = 1

    # ---- spine switches ----------------------------------------
    for i in range(1, n_spine + 1):
        sw = net.addSwitch(
            'spine%d' % i,
            sw_path='simple_switch',
            json_path=P4SRC,
            thrift_port=thrift_port_base + device_id - 1,
            device_id=device_id
        )
        spines.append(sw)
        device_id += 1

    # ---- leaf switches -----------------------------------------
    for i in range(1, n_leaf + 1):
        sw = net.addSwitch(
            'leaf%d' % i,
            sw_path='simple_switch',
            json_path=P4SRC,
            thrift_port=thrift_port_base + device_id - 1,
            device_id=device_id
        )
        leaves.append(sw)
        device_id += 1

    # ---- hosts (one benign + one attacker per leaf) -------------
    hosts = []
    for i, leaf in enumerate(leaves, 1):
        h = net.addHost(
            'h%d' % i,
            ip='10.%d.1.1/24' % i,
            mac='00:00:00:00:%02x:01' % i
        )
        net.addLink(h, leaf, bw=1000, delay='1ms')
        hosts.append(h)

    # Attacker attached to first leaf
    atk = net.addHost(
        'atk',
        ip='10.0.99.1/24',
        mac='00:00:00:00:99:01'
    )
    net.addLink(atk, leaves[0], bw=10000, delay='0ms')

    # ---- spine-leaf links (full bipartite) ----------------------
    for spine in spines:
        for leaf in leaves:
            net.addLink(spine, leaf, bw=10000, delay='1ms')

    return net, spines, leaves


def run(args):
    setLogLevel('info')
    net, spines, leaves = build_topology(
        args.n_spine, args.n_leaf, args.thrift_port)
    net.start()

    info('\n*** Spine-Leaf topology started\n')
    info('    Spines : %d\n' % args.n_spine)
    info('    Leaves : %d\n' % args.n_leaf)
    info('    Total  : %d switches\n' % (args.n_spine + args.n_leaf))

    from controller.controller import populate_tables
    populate_tables(net, topology='spine_leaf')

    if args.cli:
        from mininet.cli import CLI
        CLI(net)

    net.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Spine-Leaf Topology (Chapter 5)')
    parser.add_argument('--n-spine', type=int, default=2)
    parser.add_argument('--n-leaf',  type=int, default=3)
    parser.add_argument('--thrift-port', type=int, default=9090)
    parser.add_argument('--cli', action='store_true')
    run(parser.parse_args())
