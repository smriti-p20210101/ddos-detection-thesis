# P4-XGBoost: High-Speed Hybrid DDoS Defense

This repository provides a complete implementation and evaluation suite for the "P4-XGBoost: High-Speed Hybrid DDoS Defense" architecture.

## Overview

DDoS mitigation traditionally forces a choice between line-rate hardware defenses (fast but constrained) and centralized software intelligence (accurate but slow). P4-XGBoost bridges this gap using a two-stage hybrid architecture:

1. **P4 Data Plane**: Acts as a stateful, line-rate gatekeeper using Count-Min Sketches and Bloom filter deduplication to drastically reduce reporting overhead.
2. **Python Control Plane**: Employs an XGBoost ensemble to evaluate an 8-dimensional feature vector over a 500ms sliding window, providing high detection fidelity.

By decoupling the high-speed data plane from the high-fidelity analytical engine, P4-XGBoost achieves:
- **97.4% F1-Score Accuracy**
- **28 ms Median End-to-End Latency**

## Repository Structure

- `p4/p4_xgboost.p4`: The P4-16 data plane pipeline implementation targeting the BMv2 (v1model) architecture. Contains parse graphs, dropping logic, CMS thresholding, and the Bloom deduplication state arrays.
- `controller/app.py`: The Python SDN controller handling gRPC digest alerts, simulating 8D feature extraction, executing the XGBoost model, and issuing P4Runtime drop commands.
- `evaluation/`: A small replication package split into separate modules for paper data, tables, figures, ablations, summaries, and log generation.
- `logs/p4xgboost_replication.log`: Synthetic run log produced by the replication pipeline.
- `requirements.txt`: Python package requirements for the plotting script.

## Getting Started

### Prerequisites

To run the Python controller or evaluation scripts, ensure you have Python 3.10+ installed.

```bash
pip install -r requirements.txt
```

### 1. View Data Plane Pipeline

The P4 code resides in `p4/p4_xgboost.p4`. It models Stages 0-4 as specified in the paper, strictly enforcing line-rate limitations utilizing the `v1model.p4` library.

### 2. Run the SDN Controller

Simulate the controller receiving digests from the data plane, classifying the flow using XGBoost, and mitigating the threat:

```bash
python -m controller.app
```

## Results Replicated

- **Table 2 & 3**: Confusion Matrix and Detailed Accuracy metrics per attack typology.
- **Table 4**: 28.0 ms end-to-end latency validation mapped against the 50 ms SLA.
- **Figures 4 & 5**: ROC Curve (AUC 0.986) and XGBoost Feature Importance.
- **Figures 6 & 7**: Comparison against Jaqen, FlowLens, POSEIDON, and Gossip models.
- **Ablation Studies 1-6**: Comprehensive breakdown of the architectural constraints governing feature limits, CMS SRAM granularity width, Bloom deduplication offload, XGBoost tree-depth parameterization, packet thresholds ($T$), and temporal decay intervals ($W$).

## Generated Artifacts

- `evaluation_output/fig_4_roc_curve.png`
- `evaluation_output/fig_5_feature_importance.png`
- `evaluation_output/fig_6_latency_compare.png`
- `evaluation_output/fig_7_accuracy_compare.png`
- `evaluation_output/summary.json`
- `logs/p4xgboost_replication.log`
