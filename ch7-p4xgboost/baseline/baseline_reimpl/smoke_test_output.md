# SMOKE TEST OUTPUT -- SYNTHETIC DATA, NOT THESIS RESULTS

# Table 7.6 (functional-metrics-only replacement)

**Scope:** functional re-creations of each baseline's core mechanism,
scored on [DATASET] using the same temporal 80/20 split as P4-XGBoost.
Throughput and latency are intentionally excluded -- see README.md.

| System | Accuracy | Precision | Recall | F1 | FPR | FNR | Memory (bytes) |
|---|---|---|---|---|---|---|---|
| Jaqen-lite | 0.923 | 1.000 | 0.621 | 0.766 | 0.000 | 0.379 | 12,416 |
| POSEIDON-lite | 0.941 | 0.993 | 0.714 | 0.831 | 0.001 | 0.286 | 12,416 |
| FlowLens-lite | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 20,480 |

*Replace `[DATASET]` above with the actual CIC-DDoS2019 subset/date used, and cite this table's provenance (functional re-creation, not authors' code) directly beneath it in the thesis, per README.md.*