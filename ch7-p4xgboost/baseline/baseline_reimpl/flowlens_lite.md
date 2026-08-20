# FlowLens -> flowlens_lite mapping notes

**Source:** Barradas, Santos, Rodrigues, Signorello, Ramos, Madeira.
"FlowLens: Enabling Efficient Flow Classification for ML-based Network
Security Applications." NDSS 2021.

**Public code:** github.com/dmbb/FlowLens -- includes an "adapted" BMv2
version of the Flow Marker Accumulator (README: "due to NDA concerns, we
make public this adapted version of our code that can be run on the P4's
BMV2 behavioral model"), plus Python profiling/classification scripts. The
repo flags its own end-to-end BMv2 example as unfinished.

## The conceptual mismatch -- state this explicitly in the thesis

FlowLens was designed and evaluated for three use cases, **none of which is
DDoS defence**:
1. Covert-channel detection (Facet/DeltaShaper multimedia protocol tunneling)
2. Website fingerprinting (encrypted-tunnel traffic classification)
3. P2P botnet chatter detection (benign P2P apps vs. Waledac/Storm botnets)

All three are per-flow *classification* problems using packet-length and
inter-packet-timing distributions as features -- the same general
*mechanism* a DDoS flood detector needs (distinguishing "normal" packet-size
distributions from anomalous ones), which is why it's a defensible
functional-comparison baseline. But it is **not** a DDoS system in its
original form, and Table 7.6 (or its replacement) should carry a footnote
to this effect rather than presenting FlowLens as a peer DDoS defence
architecture on equal footing with Jaqen/POSEIDON.

| Paper concept | This re-creation | Deliberately simplified/omitted |
|---|---|---|
| Flow Marker Accumulator: quantization (`bin(QL,PL) = PL >> QL`) + truncation (top-N bins) (§IV-A) | `flowlens_lite.p4`'s register grid, `QL=4`, `NUM_BINS=10` -- values taken directly from the paper's own best-reported covert-channel configuration (Table III, Fig. 8) | Truncation here keeps the *first* 10 quantized bins rather than the *most informative* 10 (which the paper's Bayesian profiler selects per-application from training data) |
| Automatic profiler (Bayesian optimisation over QL/truncation configs, §V) | Not implemented; fixed QL/truncation | A from-scratch Hyperopt-based profiler is out of scope; if time allows, a coarse grid search over `QL ∈ {2,3,4,5,6}` and `NUM_BINS ∈ {5,10,20}` (mirroring the paper's own explored range) would strengthen this baseline meaningfully |
| Classifier: XGBoost (covert channels) / Multinomial NB (website fingerprinting) / Random Forest (botnet chatter) | `RandomForestClassifier` (sklearn), matching the *botnet-chatter* use case -- the closest of the three to a flooding-detection problem | Only one classifier choice is evaluated; an ablation matching each of the paper's three classifiers against the DDoS task could be added if useful |
| Inter-packet-timing distribution (used for botnet chatter, §VII-F) | Not implemented -- only packet-length histogram | Timing-based features are exactly what P4-XGBoost's own inter-arrival-time feature already captures (Table 7.1) and are known from Ch7's own ablation 1 to matter for Slowloris; consider adding an IPT histogram column here for a fairer fight against P4-XGBoost on that attack type specifically |

## Recommendation if committee pushes back on FlowLens as a baseline

If an examiner objects that FlowLens isn't a DDoS system, two defensible
responses:
1. Keep it, but retitle its row "FlowLens (flow-classification mechanism,
   repurposed for DDoS)" and cite this doc's mismatch explanation directly.
2. Replace it with a genuinely DDoS/IDS-oriented, BMv2-mappable ML-in-switch
   baseline with public code -- e.g. a decision-tree-to-match-action-table
   system (SwitchTree, pForest, Planter-style) or a NetBeacon-style RF/XGB
   mapping -- which also ties more naturally into Chapter 7's own
   XGBoost-in-the-loop theme.
