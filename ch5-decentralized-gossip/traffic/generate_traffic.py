#!/usr/bin/env python3
"""
generate_traffic.py

Traffic generation matching paper Section 5.3:

  Background (benign):
    - iperf3 UDP streams from benign hosts
    - Baseline throughput: 50 Mbps per link
    - Long-lived flows simulating steady application traffic

  Attack traffic (Section 5.3, Table 6):
    - 0x (baseline): no attack       — 0 pps
    - 1x (low)     : ~100 k pps
    - 2x (medium)  : ~300 k pps
    - 3x (high)    : ~500 k pps  (saturates BMv2)

  Attack source: CIC-DDoS2019 PCAP traces replayed via
  tcpreplay from the attacker host.

Reference:
  Smriti Smriti et al., ACM Journal, 2026, Section 5.3.
"""

import subprocess
import threading
import time
import argparse
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [TRAFFIC] %(message)s'
)
log = logging.getLogger(__name__)

# ---- Attack rate levels from Table 6 -------------------------
ATTACK_RATES = {
    '0x': 0,
    '1x': 100_000,    # ~100k pps
    '2x': 300_000,    # ~300k pps
    '3x': 500_000,    # ~500k pps — saturates BMv2 buffer
}

# ---- Background traffic (paper: 50 Mbps per link) ------------
BACKGROUND_BITRATE = '50M'
BACKGROUND_DURATION = 120      # seconds


def start_background_traffic(net, benign_hosts, victim_ip,
                              duration=BACKGROUND_DURATION):
    """
    Launch iperf3 UDP streams from each benign host.
    Paper Section 5.3: 'sustained, long-lived UDP streams
    from benign hosts toward a baseline throughput of 50 Mbps.'
    """
    threads = []
    for i, host_name in enumerate(benign_hosts):
        host = net.get(host_name)
        port = 5200 + i
        # iperf3 server on victim
        server_cmd = 'iperf3 -s -p %d -D' % port
        victim = net.get('h1')
        victim.cmd(server_cmd)

        # iperf3 client from benign host
        client_cmd = (
            'iperf3 -c %s -p %d -u -b %s -t %d &'
            % (victim_ip, port, BACKGROUND_BITRATE, duration)
        )
        host.cmd(client_cmd)
        log.info('Started background stream: %s → %s:%d',
                 host_name, victim_ip, port)

    return threads


def replay_attack_traffic(net, attacker_host, victim_ip,
                           pcap_file, rate_label='1x',
                           duration=30):
    """
    Replay CIC-DDoS2019 PCAP at the specified attack intensity
    using tcpreplay from the attacker host.

    Paper Table 6 attack rates:
      1x ≈ 100k pps, 2x ≈ 300k pps, 3x ≈ 500k pps

    Args:
        pcap_file  : Path to CIC-DDoS2019 PCAP
                     (download from Section C.4 of Appendix)
        rate_label : '0x' | '1x' | '2x' | '3x'
    """
    pps = ATTACK_RATES.get(rate_label, 100_000)
    if pps == 0:
        log.info('0x baseline: no attack traffic injected')
        return None

    atk = net.get(attacker_host)
    # tcpreplay with packets-per-second limit matching paper
    cmd = (
        'tcpreplay --intf1=%s-eth0 '
        '--pps=%d '
        '--duration=%d '
        '--loop=0 '
        '%s &'
        % (attacker_host, pps, duration, pcap_file)
    )
    atk.cmd(cmd)
    log.info('Attack started: %s rate=%s (%d pps)',
             attacker_host, rate_label, pps)
    return pps


def run_experiment(net, config: dict):
    """
    Run a complete traffic experiment matching paper Table 6.

    Config keys:
      victim_ip     : target host IP
      attacker      : attacker host name
      benign_hosts  : list of benign host names
      pcap_file     : path to CIC-DDoS2019 PCAP
      rate_label    : attack intensity ('0x'-'3x')
      duration      : experiment duration in seconds
    """
    victim_ip    = config['victim_ip']
    attacker     = config['attacker']
    benign_hosts = config['benign_hosts']
    pcap_file    = config['pcap_file']
    rate_label   = config.get('rate_label', '1x')
    duration     = config.get('duration', 60)

    log.info('=== Experiment: rate=%s, duration=%ds ===',
             rate_label, duration)

    # Phase 1: start background traffic
    start_background_traffic(
        net, benign_hosts, victim_ip, duration)
    time.sleep(2)   # let flows establish

    # Phase 2: inject attack
    replay_attack_traffic(
        net, attacker, victim_ip, pcap_file,
        rate_label, duration)

    # Phase 3: wait for experiment to complete
    time.sleep(duration)
    log.info('Experiment complete')


def generate_synthetic_attack(net, attacker_host,
                               victim_ip, pps=100_000,
                               duration=30):
    """
    Generate synthetic UDP flood without a PCAP file.
    Uses hping3 for controlled SYN/UDP flood.
    Used when CIC-DDoS2019 PCAP is not available.

    Paper Section 5.3: 'custom packet injection methods
    to generate packets containing attack traces.'
    """
    atk = net.get(attacker_host)
    # UDP flood at specified pps
    interval_us = max(1, int(1_000_000 / pps))
    cmd = (
        'hping3 --udp -p 80 '
        '--faster '
        '--rand-source '
        '-d 64 '
        '--interval u%d '
        '-c %d '
        '%s &'
        % (interval_us, pps * duration, victim_ip)
    )
    atk.cmd(cmd)
    log.info('Synthetic UDP flood: %s → %s @ %d pps',
             attacker_host, victim_ip, pps)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Traffic generator for Chapter 5 experiments')
    parser.add_argument(
        '--rate', choices=['0x', '1x', '2x', '3x'],
        default='1x',
        help='Attack intensity (Table 6)')
    parser.add_argument(
        '--duration', type=int, default=60,
        help='Experiment duration in seconds')
    parser.add_argument(
        '--pcap',
        default='data/CICDDoS2019_sample.pcap',
        help='Path to CIC-DDoS2019 PCAP file')
    args = parser.parse_args()
    log.info('Rate: %s (%d pps), Duration: %ds',
             args.rate, ATTACK_RATES[args.rate], args.duration)
