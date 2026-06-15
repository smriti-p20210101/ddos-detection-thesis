#!/usr/bin/env python3
"""
controller.py

P4Runtime controller implementing:
  - Table population for forwarding
  - Anti-Entropy gossip (Algorithm 2): periodic push-pull sync
  - Rumor-Mongering gossip (Algorithm 3): event-driven alert

Both gossip protocols from:
  Smriti Smriti et al., ACM Journal, 2026,
  Algorithms 2 and 3, Section 3.3.
"""

import threading
import time
import socket
import struct
import random
import logging
from collections import defaultdict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CTRL] %(levelname)s %(message)s'
)
log = logging.getLogger(__name__)

# ---- Gossip protocol parameters (Section 5.4) ----------------
ANTI_ENTROPY_INTERVAL = 0.1   # Δt = 100 ms
RUMOUR_STOP_PROB      = 0.5   # 1/k, k=2
FLAG_ALERT            = 1
FLAG_SYNC             = 2
GOSSIP_PORT           = 9999


class GossipState:
    """
    Shared threat database across all switches.
    Algorithm 2/3: local suspect list that is merged on receipt.
    """
    def __init__(self):
        self._lock    = threading.Lock()
        self._suspects = {}    # { src_ip: timestamp }
        self._alert_status = {}  # { gossip_id: 'hot'|'cold' }

    def add_suspect(self, src_ip: int):
        with self._lock:
            self._suspects[src_ip] = time.time()
            log.info('New suspect: %s', socket.inet_ntoa(
                struct.pack('!I', src_ip)))

    def get_all(self):
        with self._lock:
            return dict(self._suspects)

    def merge(self, remote_suspects: dict):
        """Algorithm 2, lines 7-11: merge received state."""
        new = []
        with self._lock:
            for ip, ts in remote_suspects.items():
                if ip not in self._suspects:
                    self._suspects[ip] = ts
                    new.append(ip)
        return new

    def mark_hot(self, gossip_id: int):
        with self._lock:
            self._alert_status[gossip_id] = 'hot'

    def mark_cold(self, gossip_id: int):
        with self._lock:
            self._alert_status[gossip_id] = 'cold'

    def is_hot(self, gossip_id: int) -> bool:
        with self._lock:
            return self._alert_status.get(gossip_id) == 'hot'


class AntiEntropyThread(threading.Thread):
    """
    Algorithm 2: Deterministic Anti-Entropy push-pull.

    Every Δt seconds:
      1. Select a random neighbour
      2. Send full local state (SYNC gossip packet)
    On receipt of SYNC:
      3. Merge remote state with local
      4. Install block rules for new suspects
    """
    def __init__(self, switches, state: GossipState,
                 interval=ANTI_ENTROPY_INTERVAL):
        super().__init__(daemon=True)
        self.switches = switches   # list of (name, thrift_port)
        self.state    = state
        self.interval = interval
        self._stop    = threading.Event()

    def run(self):
        log.info('Anti-Entropy thread started (Δt = %.3f s)',
                 self.interval)
        while not self._stop.is_set():
            # Algorithm 2, line 3: select random neighbour
            if len(self.switches) > 1:
                peer = random.choice(self.switches)
                suspects = self.state.get_all()
                # Algorithm 2, lines 4-5: push local state
                self._send_sync(peer, suspects)
            time.sleep(self.interval)

    def _send_sync(self, peer, suspects: dict):
        """Serialize and send SYNC gossip to peer."""
        try:
            sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM)
            # Pack: flag(1B) + count(2B) + [ip(4B) + ts(8B)]*n
            count = len(suspects)
            data  = struct.pack('!BH', FLAG_SYNC, count)
            for ip, ts in suspects.items():
                data += struct.pack('!Id', ip, ts)
            sock.sendto(data, ('127.0.0.1', peer['port']))
            sock.close()
        except Exception as e:
            log.debug('SYNC send failed: %s', e)

    def stop(self):
        self._stop.set()


class RumorMongeringThread(threading.Thread):
    """
    Algorithm 3: Probabilistic Rumor-Mongering.

    Triggered when a new ALERT is detected or received:
      Status(A) = Hot
      while Hot:
        select random neighbour
        send ALERT gossip packet
        if target already knows A:
          with prob 1/k: Status(A) = Cold
    """
    def __init__(self, switches, state: GossipState,
                 stop_prob=RUMOUR_STOP_PROB):
        super().__init__(daemon=True)
        self.switches  = switches
        self.state     = state
        self.stop_prob = stop_prob
        self._queue    = []
        self._lock     = threading.Lock()
        self._stop     = threading.Event()

    def trigger(self, gossip_id: int, src_ip: int):
        """Called when a new alert is detected locally."""
        self.state.mark_hot(gossip_id)
        with self._lock:
            self._queue.append((gossip_id, src_ip))
        log.info('Rumor triggered: gossip_id=%d src=%s',
                 gossip_id,
                 socket.inet_ntoa(struct.pack('!I', src_ip)))

    def run(self):
        log.info('Rumor-Mongering thread started '
                 '(stop_prob=%.2f)', self.stop_prob)
        while not self._stop.is_set():
            with self._lock:
                pending = list(self._queue)
                self._queue.clear()

            for gossip_id, src_ip in pending:
                if self.state.is_hot(gossip_id):
                    self._spread(gossip_id, src_ip)

            time.sleep(0.001)   # 1 ms polling loop

    def _spread(self, gossip_id: int, src_ip: int):
        """Algorithm 3, lines 4-9: spread to random peer."""
        if not self.switches:
            return

        peer     = random.choice(self.switches)
        ack      = self._send_alert(peer, gossip_id, src_ip)

        # Algorithm 3, line 7-9: stop condition
        if ack:   # peer already knew the alert
            if random.random() < self.stop_prob:
                self.state.mark_cold(gossip_id)
                log.debug('Rumor %d turned cold', gossip_id)
            else:
                with self._lock:
                    self._queue.append((gossip_id, src_ip))
        else:
            # Peer did not know — keep spreading
            with self._lock:
                self._queue.append((gossip_id, src_ip))

    def _send_alert(self, peer, gossip_id: int,
                    src_ip: int) -> bool:
        """Send ALERT and return True if peer ACK (already knew)."""
        try:
            sock = socket.socket(socket.AF_INET,
                                  socket.SOCK_DGRAM)
            sock.settimeout(0.05)
            data = struct.pack('!BII', FLAG_ALERT,
                               gossip_id, src_ip)
            sock.sendto(data, ('127.0.0.1', peer['port']))
            try:
                ack, _ = sock.recvfrom(4)
                knew   = struct.unpack('!B', ack)[0]
                return bool(knew)
            except socket.timeout:
                return False
        except Exception as e:
            log.debug('ALERT send failed: %s', e)
            return False
        finally:
            sock.close()

    def stop(self):
        self._stop.set()


def populate_tables(net, topology='baseline'):
    """
    Install IPv4 forwarding rules into each switch via
    simple_switch_CLI (Thrift API).
    Called after net.start() in each topology script.
    """
    import subprocess

    log.info('Populating forwarding tables for %s', topology)

    if topology == 'baseline':
        # s1=core, s2-s4=edge; routes based on host subnet
        rules = {
            's1': [
                ('10.0.1.0/24', 2),   # → s2
                ('10.0.2.0/24', 3),   # → s3
                ('10.0.3.0/24', 4),   # → s4
            ],
            's2': [
                ('10.0.1.0/24', 1),   # → h1
                ('0.0.0.0/0',   2),   # default → core
            ],
            's3': [
                ('10.0.2.0/24', 1),   # → h2
                ('0.0.0.0/0',   2),
            ],
            's4': [
                ('10.0.3.0/24', 1),   # → h3
                ('0.0.0.0/0',   2),
            ],
        }
        _install_rules(net, rules)

    elif topology == 'spine_leaf':
        # ECMP-style rules installed per spine/leaf
        log.info('Spine-leaf table population (ECMP routing)')
        _install_ecmp_rules(net)

    elif topology == 'deep_tree':
        log.info('Deep-tree table population')
        _install_deep_tree_rules(net)


def _install_rules(net, rules: dict):
    """Install LPM forwarding rules via simple_switch_CLI."""
    for sw_name, entries in rules.items():
        sw = net.get(sw_name)
        for prefix, port in entries:
            cmd = (
                'table_add ipv4_fwd forward '
                '%s => %d' % (prefix, port)
            )
            _thrift_cmd(sw.thrift_port, cmd)


def _thrift_cmd(thrift_port: int, cmd: str):
    """Send a single command via simple_switch_CLI."""
    import subprocess
    full_cmd = (
        'echo "%s" | simple_switch_CLI --thrift-port %d'
        % (cmd, thrift_port)
    )
    subprocess.run(full_cmd, shell=True,
                   stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)


def _install_ecmp_rules(net):
    """Placeholder for spine-leaf ECMP rule installation."""
    log.info('ECMP rules: see configs/spine_leaf_rules.json')


def _install_deep_tree_rules(net):
    """Placeholder for deep-tree rule installation."""
    log.info('Deep-tree rules: see configs/deep_tree_rules.json')
