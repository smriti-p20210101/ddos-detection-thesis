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

## Repository Structure

| Directory | Chapter | Paper |
|---|---|---|
| `ch3-entropy-p4/` | Ch. 3 — Entropy-Based P4 Detection | IEEE LCN 2023 |
| `ch4-gossip-protocols/` | Ch. 4 — Gossip Protocol Comparison | AINA 2025 |
| `ch5-decentralized-gossip/` | Ch. 5 — Decentralised Gossip at Scale | ACM Trans. 2026 |
| `ch6-cooperative-multops/` | Ch. 6 — Cooperative MULTOPS | AINA 2026 |
| `ch7-ml-sdn/` | Ch. 7 — ML-SDN Detection Latency | ICOIN 2025 |
| `ch8-p4xgboost/` | Ch. 8 — P4-XGBoost Hybrid Defence | Under preparation |
| `ch9-continual-mamba/` | Ch. 9 — Continual Mamba IoT IDS | Under preparation |
| `ch10-random-forest/` | Ch. 10 — Random Forest + PBR | Under preparation |

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
