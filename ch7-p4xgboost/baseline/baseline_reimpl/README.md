# Functional-Metric Baseline Re-creations for Chapter 7 (Option A / Stage 2)

## Purpose and scope

This package implements **Option A** from the feasibility assessment: a
**functional-mechanism re-creation** of Jaqen, POSEIDON, and FlowLens's core
detection/mitigation logic on the same BMv2/Mininet testbed used for
P4-XGBoost, evaluated **only on metrics BMv2 can faithfully produce**:

- Accuracy, Precision, Recall, F1
- False Positive Rate / False Negative Rate
- Data-plane memory footprint (bytes of register/table state)

**Explicitly excluded:** throughput, line-rate claims, and end-to-end
latency comparisons against the original papers. BMv2 is a software
reference switch; it cannot reproduce Barefoot Tofino ASIC performance, and
presenting BMv2 timings next to Tofino timings would repeat the exact
"environment-normalised" overstatement flagged in the feasibility review.

## Required wording change for the thesis text

Replace the current §7.2/§7.6.3 claim:

> "...reproduced in the same testbed rather than cited from their original
> papers... to ensure a fair, environment-normalised comparison."

with:

> "The core detection/mitigation mechanism of each baseline was re-implemented
> on the same BMv2/Mininet/CIC-DDoS2019 testbed used for P4-XGBoost, following
> the algorithmic description in the respective paper. Because the original
> artifacts target Barefoot Tofino and are wholly or partly unavailable
> (POSEIDON: no public code; Jaqen: SYN-proxy module only, no sketch/resource-
> manager code; FlowLens: BMv2 flow-marker accumulator only, no DDoS
> classifier), these are **functional re-creations of the published mechanism,
> not reproductions of the authors' code or hardware results**. Comparisons
> are restricted to detection accuracy, FPR/FNR, and data-plane memory
> footprint; throughput and latency are not compared across systems because
> BMv2 cannot reproduce Tofino line-rate behaviour."

## What is deliberately NOT reproduced (and why)

| System | Original component dropped here | Why |
|---|---|---|
| Jaqen | Network-wide MIP resource manager (§6 of the paper); full universal-sketch library (only a 2-metric CMS approximation is built) | Requires a multi-switch ISP topology and a MIP solver; out of scope for a single-switch functional comparison |
| POSEIDON | ILP-based primitive placement across switch+server (§V); `puzzle` (CAPTCHA) action | Placement optimisation assumes a hardware-constrained multi-stage pipeline that BMv2 does not have; puzzle is server-only in the original and orthogonal to data-plane detection |
| FlowLens | Bayesian-optimisation automatic profiler (§V); multi-application coverage (this repo only targets the DDoS binary-classification adaptation, since FlowLens was not built for DDoS) | The profiler searches quantization/truncation configurations; here fixed QL/truncation values informed by the paper's own reported sweet spots (QL=4, top-10 bins) are used instead |

This table should be reproduced (or referenced) in the thesis text near
Table 7.6 so the comparison's scope is transparent to examiners.

## Directory layout

```
p4/            BMv2 (v1model, P4_16) data-plane programs, one per baseline
controller/    Python control-plane logic for each baseline (P4Runtime-style)
eval/          Offline evaluation harness (pure Python) mirroring the P4
               + controller logic, for batch scoring against a labelled
               CIC-DDoS2019 flow CSV without needing a live Mininet run
results/       Output comparison tables (functional metrics only)
docs/          Per-system mapping notes (algorithm -> P4/Python translation)
```

## How to use this with real CIC-DDoS2019 data

1. Export CIC-DDoS2019 (or your existing CICFlowMeter-derived CSV from the
   Ch7 XGBoost pipeline) with at least these columns per flow:
   `src_ip, dst_ip, src_port, dst_port, protocol, syn_count, ack_count,
   fin_count, rst_count, pkt_lengths (list or histogram), flow_duration,
   inter_arrival_mean, inter_arrival_std, label`
   (`eval/extract_features.py` shows the exact schema and will build the
   `pkt_lengths` histogram from raw per-packet records if you only have
   packet-level CSVs.)
2. Run `python3 eval/evaluate_baselines.py --data your_flows.csv --out results/table_7_6_functional.md`
3. The script scores Jaqen-lite, POSEIDON-lite, and FlowLens-lite using the
   *same* train/test temporal split already used for P4-XGBoost (first 80%
   of capture duration = train, last 20% = test — set with `--split-col
   timestamp`), and writes a Markdown table formatted as a drop-in
   replacement for Table 7.6's functional columns.
4. For the P4-side artifacts (`p4/*.p4`), compile with `p4c-bm2-ss` against
   your BMv2/Mininet setup and validate against the offline Python logic in
   `eval/` (the offline logic is written to mirror the P4 control-flow
   exactly, so results should match to within the CMS hash-collision noise
   described in each `docs/*.md` file).

A synthetic smoke-test dataset is included (`eval/smoke_test.py`) purely to
confirm the pipeline executes end-to-end. **Its output is not thesis data**
— it is randomly generated and exists only to catch code errors before you
run against real CIC-DDoS2019 flows.
