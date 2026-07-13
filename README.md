# DDoS Detection Thesis — Source Code Repository

**Thesis:** Towards Cooperative, Decentralised, and 
Machine Learning-Assisted DDoS Defence in 
Programmable Networks

**Author:** Smriti Arora  
**Supervisor:** Dr. HariBabu Kotakula  
**Institution:** BITS Pilani, Pilani Campus  
**Degree:** Doctor of Philosophy, CSIS  
**Year:** 2026  

---

## Overview

This repository contains the complete source code,
experimental scripts, P4 programs, and configuration
files for all eight research contributions presented
in the thesis. Each chapter directory is 
self-contained with its own `README.md` describing
setup and execution steps.

---

| Directory | Chapter | Topic | Headline result |
|---|---|---|---|
| [`ch3-entropy-p4/`](ch3-entropy-p4/) | 3 | Entropy-based DDoS detection in the P4 data plane (EWMA/EWMD, Count-Min Sketch) | SYN flood detected within 2 observation windows, sub-ms latency |
| [`ch4-gossip-protocols/`](ch4-gossip-protocols/) | 4 | Epidemic vs. probability-based gossip dissemination in P4 | F1 = 0.935 on a 5-switch topology |
| [`ch5-decentralized-gossip/`](ch5-decentralized-gossip/) | 5 | Anti-Entropy vs. Rumor-Mongering at production scale | 70 ms latency invariant to 150 switches, F1 = 0.904 |
| [`ch6-cooperative-multops/`](ch6-cooperative-multops/) | 6 | Cooperative MULTOPS for asymmetric-routing robustness | 100% detection, 0% false positives |
| [`ch7-ml-sdn/`](ch7-ml-sdn/) | 7 | Decision-Tree SDN detection latency decomposition | 0.22 s (fast) → 4.75 s (flood) detection time |
| [`ch8-p4xgboost/`](ch8-p4xgboost/) | 8 | Hybrid P4 + XGBoost two-stage defence | 97.4% accuracy, 28 ms median latency, 8% controller CPU |
| [`ch9-continual-mamba/`](ch9-continual-mamba/) | 9 | Continual learning (Mamba + KAN + EWC) for IoT IDS | Ak = 78.38%, BWT = −21.99 (CIC-IoT2023) |
| [`ch10-random-forest/`](ch10-random-forest/) | 10 | Correlation-aware Random Forest + Packet Byte Ratio | 99.4% in-distribution, 25.32% cross-dataset |

---

## General notes for anyone extending this work

- **P4/Mininet chapters (3, 4, 5, 8)** require a working P4 toolchain (`p4c` compiler)
  and the BMv2 software switch (`simple_switch` / `simple_switch_grpc`), plus Mininet.
  These are **not** pip-installable — see the Docker section in each of those
  chapters' READMEs.
- **Ch.6** uses the Click Modular Router instead of P4 — it has its own, separate
  toolchain (see `ch6-cooperative-multops/README.md`).
- **Ch.7, 9, 10** are pure Python/ML projects and only need the pip packages in
  each `requirements.txt`.
- Dataset download links (CIC-DDoS2019, CICIDS2017, CIC-IoT2023, ToN-IoT, Kaggle
  DDoS-SDN) are **not redistributed** in this repo — each chapter README links to
  the original source.
- Every chapter directory is independent: clone the repo, `cd` into the chapter you
  care about, and follow that chapter's README from a clean environment (or its
  Dockerfile) — you don't need the other seven chapters' dependencies installed.
---

## Key Results

| Chapter | Key Result |
|---|---|
| Ch. 3 | SYN flood detected within 2 observation windows at sub-millisecond latency |
| Ch. 4 | Epidemic gossip converges faster; probability-based uses lower bandwidth; F1 = 0.935 |
| Ch. 5 | 70 ms detection latency invariant to network size; F1 = 0.904 across 150 switches |
| Ch. 6 | 100% flood detection; 0% false positives for legitimate asymmetric sessions |
| Ch. 7 | ML inference < 1 ms; controller communication delay dominates (0.22 s → 4.75 s) |
| Ch. 8 | 97.4% accuracy at 28 ms median latency; 8% controller CPU load |
| Ch. 9 | Mamba+KAN+EWC: Ak = 78.38%, BWT = −21.99 on CIC-IoT2023 |
| Ch. 10 | PBR achieves 99.4% on CICIDS2017; cross-dataset accuracy 25.32% |

---

## Datasets

All datasets used in this thesis are publicly 
available. They are not redistributed here.

| Dataset | Used in | Download |
|---|---|---|
| CIC-DDoS2019 | Ch. 3, 4, 5, 7, 8, 10 | https://www.unb.ca/cic/datasets/ddos-2019.html |
| CICIDS2017 | Ch. 9, 10 | https://www.unb.ca/cic/datasets/ids-2017.html |
| CIC-IoT2023 | Ch. 9 | https://www.unb.ca/cic/datasets/iotdataset-2023.html |
| ToN-IoT | Ch. 9 | https://research.unsw.edu.au/projects/toniot-datasets |
| Kaggle DDoS SDN | Ch. 10 | [https://www.kaggle.com/datasets/](https://www.kaggle.com/datasets/dhoogla/cicddos2019) |

---

## Requirements

### P4 Chapters (3, 4, 5, 8)
- Python 3.10+
- Mininet 2.3.0
- BMv2 software switch
- p4c compiler

Installation:
```bash
# BMv2
https://github.com/p4lang/behavioral-model

# p4c
https://github.com/p4lang/p4c
```

### ML Chapters (7, 9, 10)
Each chapter directory contains its own requirements.txt.
See the chapter README.md for installation instructions.

### Chapter 6
- Click Modular Router 2.0
- Python 3.10+

---

## Publications

**Published**
1. Smriti Arora, HariBabu Kotakula, Lingesh Kumaar, 
   Rahul Kumar. *Early Detection of DDoS Attacks in 
   Networks Leveraging Data Plane Programming.* 
   IEEE LCN 2023. DOI: 10.1109/LCN58197.2023.10223404

2. Smriti Smriti, HariBabu Kotakula, Sanyam Garg. 
   *DDoS Attack Detection in Data Plane.* 
   AINA 2025. DOI: 10.1007/978-3-031-82838-6_11

3. Smriti Arora, HariBabu Kotakula, Shrinivas Choudhary.
   *Assessing the Impact of ML-Based DDoS Attack 
   Detection on SDN Network Performance.* ICOIN 2025.

4. Smriti Smriti, Arnav Dham, HariBabu Kotakula.
   *Decoupled State Aggregation for Asymmetric DDoS 
   Detection using MULTOPS.* AINA 2026.

**Under Review**

5. Smriti Smriti, HariBabu Kotakula, Mohaneesh Raj 
   Pradhan, Nitin Varyani. *Scalable, Low-Latency, 
   Decentralized DDoS Detection Using Gossip Protocols 
   in Programmable Data Plane.* 
   ACM Transactions on Internet Technology, 2026.

---

## Licence

MIT License — see `LICENSE` file for details.

## Citation

If you use this code, please cite the relevant 
chapter paper listed above.
