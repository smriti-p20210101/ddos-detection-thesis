# Ch.4 — Gossip Protocol-Based Threat Dissemination (Epidemic vs. Probability-Based)

Compares two gossip dissemination strategies for spreading entropy-based DDoS
alerts natively in P4, on a 5-switch / 3-host Containernet topology. Corresponds
to the AINA 2025 paper (DOI: 10.1007/978-3-031-82838-6_11).

## Architecture

```
        host1        host2       host3 (targets)
          \            |            /
           s1 -------- s2 -------- s3
           |            |           |
           s4 --------- +---------- s5

  Each switch runs entropy.p4 (from Ch.3) + gossip dissemination logic.
  On detecting an anomaly, a switch clones the packet (clone3) and forwards
  it either to ALL neighbours (Epidemic) or to ONE randomly selected
  neighbour (Probability-Based), carrying the custom ddosd_t header.
```

- **Custom header `ddosd_t`**: source-IP entropy, destination-IP entropy, and a
  1-bit `alarm` field, tagged with EtherType `0x6605` (vs. `0x0800` for plain IPv4).
- **Dissemination via `clone3`**: the P4 `clone3` primitive + a `mirroring_add`
  session (configured via `simple_switch_CLI`) forwards a copy of the alert
  packet to one or more egress ports without touching the original packet.
- **Epidemic**: broadcasts the alert to all neighbouring ports.
- **Probability-based**: uses the P4 `random()` primitive to pick a single
  neighbour's mirroring session per gossip event.
- **Convergence**: both protocols converge to the same steady-state entropy
  once the update has propagated network-wide — the comparison is about *how
  fast* they get there, not the final value.

## Repository contents

```
ch4-gossip-protocols/
├── p4src/
│   ├── epidemic_gossip.p4
│   └── probability_gossip.p4
├── containernet/
│   └── topology.py        # 5 switch / 3 host Containernet topology
├── scripts/
│   ├── run_epidemic.sh
│   ├── run_probability.sh
│   └── capture_wireshark.sh
└── analysis/
    └── plot_convergence.py  # entropy-vs-packets-sampled, per-switch entropy plots
```

## Setup

### Docker (recommended — Containernet needs Docker-in-Docker)
```bash
docker build -t ch4-gossip .
docker run --rm -it --privileged -v /var/run/docker.sock:/var/run/docker.sock ch4-gossip
```

### Local install
1. P4 toolchain (p4c + BMv2) as in Ch.3.
2. Containernet (Mininet fork with Docker container hosts):
   `git clone https://github.com/containernet/containernet && cd containernet && sudo ./install.sh`
3. `pip install -r requirements.txt`

## Running
```bash
p4c --target bmv2 --arch v1model -o build p4src/epidemic_gossip.p4
sudo python3 containernet/topology.py --protocol epidemic
sudo bash scripts/run_epidemic.sh
# repeat with probability_gossip.p4 / run_probability.sh
python3 analysis/plot_convergence.py --epidemic logs/epidemic.csv --probability logs/probability.csv
```

## Expected output
- Destination entropy declining toward 0 under simulated attack for both
  protocols, with Epidemic converging faster (fewer packets sampled).
- Per-switch entropy trace showing all 5 switches converging to within ~0.1
  of each other once gossip has propagated.
- F1 = 0.935 for the better-performing configuration on this topology.

## Datasets / traffic
Synthetic traffic only (Mininet/Containernet hosts, `hping3` for the attack phase).

## Citation
Smriti, K. HariBabu, S. Garg, "DDoS Attack Detection in Data Plane," AINA 2025,
LNDECT vol. 252, Springer.
