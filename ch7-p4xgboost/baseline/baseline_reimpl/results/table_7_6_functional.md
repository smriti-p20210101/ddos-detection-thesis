# Table 7.6 (functional-metrics-only replacement)

**Scope:** functional re-creations of each baseline's core mechanism,
scored on [DATASET] using the same temporal 80/20 split as P4-XGBoost.
Throughput and latency are intentionally excluded -- see README.md.

| System | Accuracy | Precision | Recall | F1 | FPR | FNR | Memory (bytes) |
|---|---|---|---|---|---|---|---|
| Jaqen-lite | 0.020 | 0.167 | 0.000 | 0.000 | 0.000 | 1.000 | 12,416 |
| POSEIDON-lite | 0.014 | 0.169 | 0.002 | 0.003 | 0.357 | 0.998 | 12,416 |
| FlowLens-lite | 0.992 | 0.993 | 0.999 | 0.996 | 0.350 | 0.001 | 20,480 |
| P4-XGBoost (Ch7, real measured -- see evaluation_output/summary.json) | 0.835 | 0.826 | 0.835 | 0.827 | 0.073 | nan | 4,224 |

*Replace `[DATASET]` above with the actual CIC-DDoS2019 subset/date used, and cite this table's provenance (functional re-creation, not authors' code) directly beneath it in the thesis, per README.md.*

## Per-attack-type breakdown (real, matching Table 7.4's structure)

| System | Type | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|---|
| Jaqen-lite | udp | 0.020 | 0.167 | 0.000 | 0.000 | 0.000 |
| Jaqen-lite | syn | 0.919 | 0.000 | 0.000 | 0.000 | 0.000 |
| POSEIDON-lite | udp | 0.013 | 0.000 | 0.000 | 0.000 | 0.357 |
| POSEIDON-lite | syn | 0.658 | 0.169 | 0.824 | 0.281 | 0.357 |
| FlowLens-lite | udp | 0.993 | 0.993 | 1.000 | 0.996 | 0.350 |
| FlowLens-lite | syn | 0.655 | 0.152 | 0.707 | 0.250 | 0.350 |