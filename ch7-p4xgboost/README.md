# P4-XGBoost: High-Speed Hybrid DDoS Defense

This repository provides a complete implementation and evaluation suite for the "P4-XGBoost: High-Speed Hybrid DDoS Defense" architecture.

## Important: this is a replication/simulation package, not a live pipeline

**Read this before setting up anything.** `controller/p4/p4runtime.py`'s
`P4RuntimeInterface` uses `time.sleep()` to emulate switch/rule-install
latency, and `controller/ml/xgboost_model.py`'s `XGBoostEnsemble` reads its
hyperparameters from `config/settings.yaml` without calling the real
`xgboost` library. There is no BMv2/gRPC switch, no Redis feature cache, and
no TRex traffic replay in this directory — the code reproduces the paper's
reported numbers, tables, and figures via a self-contained Python simulation
of the control-plane logic, not a live P4 data plane.

If you want to build the **actual** live hybrid system (real BMv2 gRPC
target + Redis + XGBoost + TRex) described in the paper, treat this
directory's `controller/` as a reference implementation of the *decision
logic* (feature vector shape, threshold behaviour, drop-rule bookkeeping)
and pair it with a real BMv2 `simple_switch_grpc` build (see Ch.5's
`Dockerfile` for the general P4/BMv2 build pattern to adapt) plus a real
`xgboost`-backed model. That's a substantial extension beyond what's
checked in here, not a small config change.

## Overview

DDoS mitigation traditionally forces a choice between line-rate hardware defenses (fast but constrained) and centralized software intelligence (accurate but slow). P4-XGBoost bridges this gap using a two-stage hybrid architecture:

1. **P4 Data Plane**: Acts as a stateful, line-rate gatekeeper using Count-Min Sketches and Bloom filter deduplication to drastically reduce reporting overhead.
2. **Python Control Plane**: Employs an XGBoost ensemble to evaluate an 8-dimensional feature vector over a 500ms sliding window, providing high detection fidelity.

By decoupling the high-speed data plane from the high-fidelity analytical engine, P4-XGBoost achieves:
- **97.4% F1-Score Accuracy**
- **28 ms Median End-to-End Latency**

(As above: these are the paper's reported live-system numbers, reproduced
here via simulation — see `evaluation_output/summary.json` for the exact
replicated figures.)

## Repository Structure

- `p4/p4_xgboost.p4`: The P4-16 data plane pipeline implementation targeting the BMv2 (v1model) architecture. Contains parse graphs, dropping logic, CMS thresholding, and the Bloom deduplication state arrays. (Reference only — not compiled/run by the simulation below.)
- `controller/app.py`: The Python SDN controller handling simulated digest alerts, extracting an 8D feature vector, running the (simulated) XGBoost model, and issuing (simulated) P4Runtime drop commands.
- `controller/core/features.py`, `controller/core/metrics.py`: feature extraction and latency/accuracy bookkeeping used by `app.py`.
- `controller/ml/xgboost_model.py`: `XGBoostEnsemble`, parameterised from `config/settings.yaml` (100 estimators, depth 6, lr 0.1, matching the paper).
- `controller/p4/p4runtime.py`: `P4RuntimeInterface`, a simulated P4Runtime client (see note above).
- `evaluation/`: A small replication package split into separate modules for paper data, tables, figures, ablations, summaries, and log generation.
- `evaluation_output/`: Already-generated figures/summary matching the paper's Tables/Figures — regenerate via `evaluation/` if you change anything.
- `logs/p4xgboost_replication.log`: Synthetic run log produced by the replication pipeline.
- `tests/test_model.py`: `pytest` sanity checks on `XGBoostEnsemble`'s classification behaviour on hand-picked malicious/benign feature vectors.
- `config/settings.yaml`: ML hyperparameters, loaded by `XGBoostEnsemble`.
- `requirements.txt`: Python package requirements.

## Getting Started

### Prerequisites

Python 3.10+.

```bash
pip install -r requirements.txt
```

### 1. View Data Plane Pipeline

The P4 code resides in `p4/p4_xgboost.p4`. It models Stages 0-4 as specified in the paper, strictly enforcing line-rate limitations utilizing the `v1model.p4` library. (Reference/documentation only in this repo — see the note at the top of this README.)

### 2. Run the SDN Controller

Simulate the controller receiving digests from the data plane, classifying the flow using XGBoost, and mitigating the threat:

```bash
python -m controller.app
```

### 3. Run the tests

```bash
python -m pytest tests/ -v
```

### 4. Regenerate the evaluation outputs

```bash
python -m evaluation.summary      # regenerates evaluation_output/summary.json
python -m evaluation.figures       # regenerates the fig_*.png files
python -m evaluation.tables         # regenerates paper tables
```
(Check each module's `if __name__ == "__main__"` block / `--help` for exact
invocation if it differs — these are inferred from the module names in
`evaluation/`; verify against the actual entrypoints before relying on this.)

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

## Extending this chapter into a live system

If you do build the real live pipeline:
- Replace `controller/p4/p4runtime.py` with a real `p4runtime-sh`-based
  client talking to a `simple_switch_grpc` instance running
  `p4/p4_xgboost.p4`.
- Replace `controller/ml/xgboost_model.py`'s internals with a real
  `xgboost.XGBClassifier`, keeping the same `predict_proba(features)`
  interface so `controller/app.py` doesn't need to change.
- Add a Redis-backed sliding window to `controller/core/features.py` for the
  8-D feature extraction (currently likely computed in-process — check that
  file before assuming a cache layer already exists).
- Use a real traffic generator (TRex, for nanosecond-precision inter-arrival
  timing — a plain PCAP replay via `scapy`/`tcpreplay` will distort the
  inter-arrival-time feature).

## Citation

Smriti Arora, Hari Babu K, Samiksha Kaul, "P4-XGBoost: High-Speed Hybrid DDoS
Defense," Journal of Network and Computer Applications, Elsevier (in preparation).
