#!/usr/bin/env python3
"""
baseline_tree.py

Baseline Tree Topology — 1 Core switch + 3 Edge switches
Section 5.2, p4app/Mininet framework.
Used for memory sensitivity testing and functional
verification of the gossip protocol (paper Table 8,
'Small (Baseline): 4 switches').

  h1 -- s2 (edge)
          |
  h2 -- s3 (edge) -- s1 (core)
          |
  h3 -- s4 (edge)

Reference:
  Smriti Smriti et al., ACM Journal, 2026, Section 5.2.
"""

from mininet.net import Mininet
from mininet.node import Host
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from p4_mininet import P4Switch, P4Host
import argparse
import os

THISDIR = os.path.dirname(os.path.realpath(__file__))
P4SRC   = os.path.join(THISDIR, '..', 'p4', 'gossip_detect.p4')


def build_topology(thrift_port_base=9090):
    """Create and return the baseline tree topology."""
    net = Mininet(
        switch=P4Switch,
        host=P4Host,
        link=TCLink,
        controller=None
    )

    # ---- switches ------------------------------------------------
    s1 = net.addSwitch(
        's1',
        sw_path='simple_switch',
        json_path=P4SRC,
        thrift_port=thrift_port_base,
        pcap_dump=False,
        device_id=1
    )
    s2 = net.addSwitch(
        's2',
        sw_path='simple_switch',
        json_path=P4SRC,
        thrift_port=thrift_port_base + 1,
        pcap_dump=False,
        device_id=2
    )
    s3 = net.addSwitch(
        's3',
        sw_path='simple_switch',
        json_path=P4SRC,
        thrift_port=thrift_port_base + 2,
        pcap_dump=False,
        device_id=3
    )
    s4 = net.addSwitch(
        's4',
        sw_path='simple_switch',
        json_path=P4SRC,
        thrift_port=thrift_port_base + 3,
        pcap_dump=False,
        device_id=4
    )

    # ---- hosts ---------------------------------------------------
    h1 = net.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:01:01')
    h2 = net.addHost('h2', ip='10.0.2.1/24', mac='00:00:00:00:02:01')
    h3 = net.addHost('h3', ip='10.0.3.1/24', mac='00:00:00:00:03:01')
    # Attacker host for DDoS simulation
    atk = net.addHost('atk', ip='10.0.9.1/24', mac='00:00:00:00:09:01')

    # ---- links ---------------------------------------------------
    # Edge to hosts
    net.addLink(h1,  s2, bw=1000, delay='1ms')
    net.addLink(h2,  s3, bw=1000, delay='1ms')
    net.addLink(h3,  s4, bw=1000, delay='1ms')
    net.addLink(atk, s2, bw=1000, delay='1ms')

    # Edge to core
    net.addLink(s2, s1, bw=10000, delay='1ms')
    net.addLink(s3, s1, bw=10000, delay='1ms')
    net.addLink(s4, s1, bw=10000, delay='1ms')

    return net


def run(args):
    setLogLevel('info')
    net = build_topology(args.thrift_port)
    net.start()

    info('\n*** Baseline Tree topology started\n')
    info('    Switches : s1 (core), s2-s4 (edge)\n')
    info('    Hosts    : h1-h3 (benign), atk (attacker)\n')
    info('    P4 prog  : %s\n' % P4SRC)

    from controller.controller import populate_tables
    populate_tables(net, topology='baseline')

    if args.cli:
        from mininet.cli import CLI
        CLI(net)

    net.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Baseline Tree Topology (Chapter 5)')
    parser.add_argument('--thrift-port', type=int, default=9090)
    parser.add_argument('--cli', action='store_true',
                        help='Open Mininet CLI after setup')
    run(parser.parse_args())
