# Chapter 5 — Scalable, Low-Latency, Decentralised DDoS Detection Using Gossip Protocols in Programmable Data Plane

**Authors:** Smriti Smriti, HariBabu K, Mohaneesh Raj Pradhan, Nitin Varyani  
**Paper:** ACM Journal, Vol. 1, No. 1, March 2026  
**DOI:** 10.1145/nnnnnnn.nnnnnnn

---

## Overview

This directory contains the complete implementation of the
decentralised, controller-free DDoS detection framework
described in Chapter 5 of the thesis. The system embeds
Count-Min Sketch detection and gossip-based threat
dissemination entirely within the P4 data plane, achieving
**70 ms detection latency invariant to network size** across
topologies of up to 150 switches.

### Key results (paper Tables 6–9)

| Metric | Value |
|--------|-------|
| Median detection latency | **70 ms** (constant, all topologies) |
| 80% convergence (Spine-Leaf, 150 sw) | **250 ms** |
| F1 score | **0.904** (Config A) / **0.919** (Config B) |
| Max CPU at 150 switches | **< 60%** |
| Benign goodput preserved at 1× rate | **48–49 Mbps** |

---

## Directory Structure

```
ch5-decentralized-gossip/
├── p4/
│   └── gossip_detect.p4       # Main P4 program (Algorithms 1-4)
├── topologies/
│   ├── baseline_tree.py       # 1 core + 3 edge (4 switches)
│   ├── spine_leaf.py          # 2 spine + 3 leaf (best scaling)
│   └── deep_tree.py           # 1 core + 2 agg + 4 edge (worst)
├── controller/
│   └── controller.py          # Anti-Entropy + Rumor-Mongering
├── traffic/
│   └── generate_traffic.py    # iperf3 + tcpreplay attack
├── evaluation/
│   ├── compute_metrics.py     # F1, latency, convergence
│   └── scalability.py         # Table 7 scalability sweep
├── configs/
│   ├── config_a.json          # 1024 registers (4 KB)
│   └── config_b.json          # 2048 registers (8 KB)
├── requirements.txt
└── INSTALL.md
```

---

## Installation

### 1. Python dependencies
```bash
pip install -r requirements.txt
```

### 2. P4 toolchain (BMv2 + p4c)
```bash
# Follow official p4lang installation guide:
# https://github.com/p4lang/behavioral-model#installing-bmv2
# https://github.com/p4lang/p4c#getting-started

# Or use the p4app Docker image (recommended):
docker pull p4lang/p4app
```

### 3. Mininet
```bash
sudo apt-get install mininet
# or
git clone https://github.com/mininet/mininet
cd mininet && sudo ./util/install.sh -a
```

---

## Running the Experiments

### Baseline topology (4 switches, quick functional test)
```bash
sudo python topologies/baseline_tree.py --cli
```

### Spine-Leaf topology (paper best-scaling result)
```bash
sudo python topologies/spine_leaf.py \
    --n-spine 2 --n-leaf 3 --cli
```

### Deep-Tree topology (paper worst-scaling result)
```bash
sudo python topologies/deep_tree.py --cli
```

### Full scalability sweep (Table 7)
```bash
python evaluation/scalability.py \
    --topologies spine_leaf fat_star deep_tree \
    --switch-counts 25 50 100 150 \
    --attack-rate 1x \
    --output results/table7.json
```

### Traffic generation (Table 6 attack rates)
```bash
# Requires CIC-DDoS2019 PCAP — see Dataset section below
python traffic/generate_traffic.py \
    --rate 1x --duration 60 \
    --pcap data/CICDDoS2019_sample.pcap
```

---

## Gossip Protocol Selection

The P4 program supports both gossip protocols.
Select via the `gossip_flag` field in the gossip header:

| Protocol | Flag | Behaviour |
|---|---|---|
| **Rumor-Mongering** | `FLAG_ALERT = 1` | Probabilistic; triggered on new alert; stops when peer already knows (prob 1/k = 0.5) |
| **Anti-Entropy** | `FLAG_SYNC = 2` | Deterministic; periodic push-pull every 100 ms; sends full suspect list |

Set in `configs/config_a.json`:
```json
{
  "gossip_flag_alert": 1,
  "gossip_flag_sync":  2,
  "anti_entropy_interval_ms": 100,
  "rumour_stop_prob": 0.5
}
```

---

## Dataset

The CIC-DDoS2019 dataset is used for attack traffic replay
(paper Section 5.3). It is **not redistributed** here.

Download from:  
https://www.unb.ca/cic/datasets/ddos-2019.html

Place PCAP files under `data/` before running traffic scripts.

---

## Expected Results

Running `python evaluation/scalability.py` should produce
output matching paper Table 7:

```
================================================================
Table 7: Scalability Analysis
================================================================
Topology       Switches   DetLatency(ms)   80%Conv(ms)   MaxCPU%  F1
----------------------------------------------------------------
spine_leaf     25         70               160           38       0.90
spine_leaf     50         70               190           42       0.90
spine_leaf     100        70               220           47       0.90
spine_leaf     150        70               250           52       0.90
...
```

**Key finding:** Detection latency = **70 ms** across ALL
topology sizes (invariant to switch count because detection
is purely local to the ingress switch).

---

## Citation

```bibtex
@article{smriti2026acm,
  author  = {Smriti Smriti and HariBabu K and
             Mohaneesh Raj Pradhan and Nitin Varyani},
  title   = {Scalable, Low-Latency, Decentralized {DDoS}
             Detection Using Gossip Protocols in
             Programmable Data Plane},
  journal = {ACM Journal},
  volume  = {1},
  number  = {1},
  year    = {2026},
  doi     = {10.1145/nnnnnnn.nnnnnnn}
}
```
