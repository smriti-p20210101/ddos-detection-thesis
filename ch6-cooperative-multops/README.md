# Cooperative MULTOPS: Asymmetric DDoS Detection Framework

A cooperative DDoS detection framework that extends the MULTOPS algorithm to operate correctly in networks with asymmetric routing.

## Overview

Traditional MULTOPS (Multi-Level Tree for Online Packet Statistics) detects bandwidth attacks by comparing incoming and outgoing traffic rates. While effective in symmetric routing environments, it suffers from high false-positive rates when traffic follows asymmetric network paths.

This project introduces a **Cooperative MULTOPS Framework** that reconstructs a global view of network traffic by aggregating telemetry from multiple routers. By combining partial observations from distributed monitoring points, the system can accurately distinguish legitimate asymmetric traffic from malicious DDoS floods.

## Key Features

* Distributed traffic monitoring using Click Modular Router
* Lightweight UDP-based telemetry protocol
* Centralized traffic state aggregation
* Global traffic view reconstruction
* Real-time DDoS detection
* Automatic mitigation through dynamic blocklist updates
* Support for asymmetric routing environments
* Low bandwidth and computational overhead

## Architecture

```text
                 +----------------------+
                 |      Aggregator      |
                 |   (Python Service)   |
                 +----------+-----------+
                            ^
                            |
                    UDP Telemetry
                            |
                            v
+--------------------------------------------------+
|              Click Router Network                |
|                                                  |
|  +-------------+     +----------------------+    |
|  | IPRate      | --> |  Policy Enforcer     |    |
|  | Monitor     |     |                      |    |
|  +-------------+     +----------------------+    |
|                                                  |
+--------------------------------------------------+

        Attack Traffic       Legitimate Traffic
             |                     |
             v                     v
      Statistics Export     Statistics Export
```

## Problem Statement

MULTOPS relies on the assumption that:

```text
Incoming Traffic ≈ Outgoing Traffic
```

However, modern Internet routing is often asymmetric:

```text
Client ---> Router A ---> Server
Client <--- Router B <--- Server
```

Router A only sees requests, while Router B only sees responses.

As a result:

* Legitimate traffic may appear malicious.
* False positives increase significantly.
* Local detection mechanisms lose effectiveness.

This framework solves the problem by aggregating observations from multiple routers into a single global state.

## Components

### 1. Modified IPRateMonitor

Enhanced Click element responsible for:

* Monitoring packet rates
* Maintaining MULTOPS statistics
* Exporting telemetry periodically
* Serializing statistics into UDP packets

### 2. Aggregator

A Python-based centralized detection engine.

Responsibilities:

* Receive telemetry from routers
* Merge distributed traffic views
* Calculate asymmetry ratios
* Detect attacks
* Generate mitigation policies

### 3. PolicyEnforcer

Custom Click element that:

* Receives block commands
* Maintains a blocklist
* Drops malicious traffic in real time

## Detection Logic

For each monitored prefix:

```text
Ratio = Rin / Rout
```

An attack is detected if:

```text
Ratio > Threshold
```

or

```text
Rout = 0 AND Rin > RateThreshold
```

The aggregator combines statistics from multiple routers before making a decision, eliminating errors caused by partial visibility.

## Telemetry Protocol

### Header

| Field        | Size    |
| ------------ | ------- |
| Auth Key     | 4 bytes |
| Record Count | 2 bytes |

### Record

| Field         | Size      |
| ------------- | --------- |
| IP Prefix     | 4 bytes   |
| Prefix Length | 1 byte    |
| To Rate       | 4 bytes   |
| From Rate     | 4 bytes   |
| Padding       | Remaining |

Communication occurs over UDP to minimize overhead.

## Experimental Setup

### Environment

* Click Modular Router
* Python Aggregator
* WSL2
* Synthetic traffic generators

### Traffic Profiles

| Flow   | Type               | Rate       |
| ------ | ------------------ | ---------- |
| Flow A | UDP Flood          | 10,000 pps |
| Flow B | Legitimate Session | 50 pps     |

### Test Scenarios

#### Scenario 1: Baseline

* Aggregator disabled
* Attack traffic not blocked

#### Scenario 2: Cooperative Detection

* Aggregator enabled
* Attack detected and blocked

#### Scenario 3: Mixed Traffic

* Attack traffic present
* Legitimate asymmetric traffic present
* Attack blocked
* Legitimate traffic allowed

## Results

| Scenario            | Detection Rate | False Positive Rate |
| ------------------- | -------------- | ------------------- |
| Standalone MULTOPS  | 100%           | 100%                |
| Cooperative MULTOPS | 100%           | 0%                  |

### Additional Findings

* 100% detection of high-rate UDP floods
* Elimination of asymmetric-routing false positives
* Minimal telemetry bandwidth overhead
* O(1) average lookup complexity using hash maps

## Technologies Used

* C++
* Python
* Click Modular Router
* UDP Sockets
* Linux Networking APIs

## Repository Structure

```text
.
├── aggregator/
│   └── aggregator.py
│
├── click-elements/
│   ├── IPRateMonitor.cc
│   ├── IPRateMonitor.hh
│   ├── PolicyEnforcer.cc
│   └── PolicyEnforcer.hh
│
├── click-scripts/
│   ├── test_attack.click
│   └── test_full.click
│
├── docs/
│   └── paper.pdf
│
└── README.md
```

## Future Work

* Multi-router deployment across physical hosts
* Support for TCP SYN flood detection
* Adaptive thresholding
* Sketch-based compression techniques
* Integration with SDN controllers
* IPv6 support

## Authors

* Arnav Dham
* Smriti Smriti
* Hari Babu K

## Citation

If you use this work in research, please cite:

```bibtex
@article{cooperative_multops_2026,
  title={Decoupled State Aggregation for Asymmetric DDoS Detection using MULTOPS},
  author={Smriti, Smriti and Dham, Arnav and HariBabu, K},
  year={2026}
}
```
