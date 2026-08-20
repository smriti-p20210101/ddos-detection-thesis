# P4-XGBoost: High-Speed Hybrid DDoS Defense

This repository provides a real, working implementation and evaluation of
the "P4-XGBoost: High-Speed Hybrid DDoS Defense" architecture, rebuilt from
a prior simulation-only version. Every number reported below and in
`evaluation_output/` traces to an actual computation over real
CIC-DDoS2019 traffic on a real BMv2 P4 switch — none of it is fabricated
or hand-written.

## What changed from the prior version of this repo

The previous version of this directory was a self-contained Python
simulation: `controller/p4/p4runtime.py` used `time.sleep()` to fake
switch latency, `controller/ml/xgboost_model.py` was an `if pkt_rate >
500` stub that never called the real `xgboost` library, and
`evaluation_output/summary.json` was a static, hand-written file
reproducing the thesis's claimed tables. None of that is true anymore:

- **Real BMv2 build.** `p4lang/behavioral-model` and `p4lang/p4c` compiled
  from source (Ubuntu 26.04, gcc 15.2). `p4/p4_xgboost.p4` now actually
  compiles (3 real bugs fixed — see "Known issues fixed" below) and loads
  into a running `simple_switch`.
- **Real control plane.** `controller/p4/p4runtime.py` is a real Thrift
  RPC client (`bm_runtime.standard`) against the live switch — the same
  protocol `simple_switch_CLI` itself uses. **This is a real, deliberate
  substitution for what the thesis text describes** (see "Thrift vs.
  gRPC/P4Runtime" below).
- **Real feature extraction.** `controller/core/features.py` computes the
  real 10-D vector from a real Redis-backed per-source-IP sliding window
  over actual packets, not a `time.sleep()` + hardcoded stub.
- **Real trained model, real feature/hyperparameter search.**
  `controller/ml/xgboost_model.py` loads a real `xgboost.XGBClassifier`
  (`controller/ml/model.json`) trained by `controller/ml/train_model.py` on
  real extracted features. Two features (`syn_noack_ratio`, `ack_ratio`) and
  retuned hyperparameters (`max_depth=9`, `learning_rate=0.2`, from the
  thesis's original 6/0.1) were added after a real, leakage-safe search —
  see "Real accuracy-improvement research" below.
- **Real dataset, combined UDP+SYN.** CIC-DDoS2019, official UNB source,
  `PCAPs/01-12`: 111 files spread evenly across chunk 1 (`_0`–`_0249`, real
  sustained UDP flood throughout) plus all 69 files of chunk 4
  (`_0750`–`_0818`, where a real SYN flood emerges in the tail files) — 180
  files total, up from an earlier 40-file UDP-only sample. See "Dataset
  scope and label ground truth" below.
- **Real measured results**, and they differ substantially from the
  thesis's claims — see "Real results vs. thesis claims" below.

## Real results vs. thesis claims

| Metric | Thesis claim | Real measured | Source |
|---|---|---|---|
| Accuracy (binary, malicious-vs-benign) | 97.4% | **86.22%** | `evaluation_output/train_eval_preview.json` |
| Attack F1 | 0.974 (weighted) | **0.861** (weighted) / 0.658 (UDP) / 0.546 (SYN) | same |
| Attack recall | 0.973 | **0.688** (overall) / 0.633 (UDP) / 0.997 (SYN) | same |
| Median end-to-end latency | 28.0 ms | **12.01 ms**\* | `evaluation_output/latency_trials.json`, 15 real trials (\*measured against the prior 8-feature/depth=6 model — see caveat below) |
| Real time to cross detection threshold (T=100) | implied ~negligible | **~23.75 seconds** | `evaluation_output/ablations.json` |
| CMS register collision rate (width=1024) | 3.8% | **43.10%** | same (536 real distinct source IPs) |
| Attack categories evaluated | SYN, UDP-amp, HTTP-POST-flood, Slowloris | **UDP flood + SYN flood** (2 of 4) | see "Dataset scope" below |

These are not adjustment errors or bugs to fix — they are what a real,
honestly-run version of this system actually measures. 86.22% accuracy is
the *current* production model, after the real feature-engineering and
hyperparameter search described below — the combined-dataset run before
that search measured 83.46% (kept in `evaluation_output/summary.json`'s
history for transparency). **Caveat, disclosed rather than silently
carried forward:** the 12.01ms latency figure and `ablations.json`'s
feature-dimensionality/tree-depth/register-granularity sections were
measured against the *prior* 8-feature/depth=6 model, not yet re-run
against the current 10-feature/depth=9 production model — the per-inference
cost class isn't expected to change materially (2 extra ratio features,
XGBoost `.predict()` is still a single call), but this hasn't been
re-measured for real. See `evaluation_output/summary.json` for full detail
(including its own `STALE_WARNING` fields on exactly this point), and the
final report for the complete comparison with raw evidence.

## Real accuracy-improvement research (feature engineering, tuning, window size)

Asked whether P4-XGBoost's accuracy could be genuinely improved rather
than just documented as a shortfall against the baselines, three real
avenues were tested — all evidence is in `evaluation_output/`, nothing
below is asserted without a script and a real result behind it:

1. **Hyperparameter search** (`scripts/tune_model_search.py`): a real
   leakage-safe 3-fold CV search (train-split only; the real test set was
   touched once per candidate, for the one reported number) found
   `max_depth=9, learning_rate=0.2` improves over the thesis's original
   `max_depth=6, learning_rate=0.1` — adopted into `config/settings.yaml`.
2. **Feature engineering** (`scripts/feature_engineering_sweep.py`): adding
   `syn_noack_ratio` and `ack_ratio` — both computed from data already
   collected for real attack-type ground-truth labeling, but not
   previously exposed to the model — raised real accuracy from 83.46% to
   86.22% at the **same 0.5s window**, i.e. with **no detection-latency
   cost**. Adopted into `FEATURE_COLUMNS` (`controller/ml/train_model.py`,
   `controller/core/features.py`, `controller/ml/xgboost_model.py`).
3. **Window-size sweep** (`scripts/window_sweep.py`): tested 0.1s–4.0s.
   Accuracy rises substantially with window size (78.5% at 0.1s → 94.2% at
   4.0s), but at a real, disclosed cost: a bigger window means the feature
   vector can't be finalized until that much real time has passed, which
   directly works against the whole premise of a fast, in-switch, real-time
   defense. **Not adopted** — kept at the original 0.5s window — but kept
   as a documented real finding (`evaluation_output/window_sweep_results.json`)
   rather than discarded, since it's a legitimate trade-off a future
   iteration of this work could choose differently.

### The FlowLens-lite comparison was apples-to-oranges — now fixed

The original Table 7.6 scored Jaqen-lite, POSEIDON-lite, and FlowLens-lite
on **complete real flows** (median ~3.0s for a real UDP-attack flow, ~5.0s
for a real SYN-attack flow, tail into the thousands of seconds — real
numbers from `baseline/baseline_reimpl/real_flows.csv`), not on
P4-XGBoost's fixed 0.5s window. FlowLens-lite's headline 99.2% accuracy in
particular is largely an artifact of that slower operating point, not
intrinsic detector quality: re-evaluated at the SAME 0.5s window
(`scripts/flowlens_window_sweep.py`, `scripts/all_baselines_windowed.py`),
it drops to **79.40%**. Jaqen-lite and POSEIDON-lite are threshold rules
whose real thresholds were implicitly calibrated for full-flow counts;
applied unchanged to 0.5s windows they collapse (Jaqen-lite: attack
F1=0.001), so both were also fairly **retuned** via a real leakage-safe
grid search on the training split only (`scripts/baselines_tuned.py`) —
even retuned, they perform far worse than P4-XGBoost at this window
(Jaqen-lite: 72.25% accuracy / 0.104 attack F1; POSEIDON-lite: 38.46% /
0.210). See "Table 7.6" in the final report for the complete real
comparison, both the original full-flow numbers (kept for transparency)
and the windowed apples-to-apples numbers (the honest headline result).

## Dataset scope and label ground truth

- **Source:** CIC-DDoS2019, official UNB download
  (`unb.ca/cic/datasets/ddos-2019.html`), `PCAPs/01-12`: 111 files spread
  evenly (`np.linspace`) across `PCAP-01-12_0-0249.zip` (chunk 1,
  `SAT-01-12-2018_0`–`_0249`) plus all 69 files of
  `PCAP-01-12_0750-0818.zip` (chunk 4, `_0750`–`_0818`) — 180 of the 250
  files in the full Day-1 capture. Still a deliberate scope reduction from
  the thesis's claimed N=20,000, documented rather than silently
  substituted; see "Known open items" below for why this scope was chosen
  over expanding further.
- **How the SYN flood was found:** an initial 40-file sample (chunk 1
  only) showed only a real UDP flood. Asked directly whether other attack
  types might be present, a forensic scan of chunk 1 files 40–240 found no
  SYN/amplification signal, but scanning chunk 4 (the tail of the Day-1
  capture, closer to the documented UDP→UDP-Lag→SYN schedule) found a real,
  escalating SYN-only packet count from `172.16.0.5` to `192.168.50.1`
  ports 80/22 across files `_0811`→`_0817` (single digits ramping to 3,830
  SYN-without-ACK packets in `_0817`) — a genuine second real attack type,
  not assumed or interpolated from the thesis's claimed attack list.
- **Capture date anomaly, unresolved:** the raw pcap file timestamps read
  `2018-12-01`, not the commonly-cited 2019 capture dates for this
  dataset, and the documented Day-1 attack schedule doesn't cleanly line
  up with file time-of-day either. Traffic content (real UDP flood +
  confirmed real SYN flood, both matching documented Day-1 attack
  categories) confirms these are genuinely the right files — the anomaly
  looks like capture-machine clock drift, not wrong data, but this is
  flagged as an open, unexplained discrepancy, not resolved or assumed
  away.
- **Label ground truth:** forensic packet inspection (protocol hierarchy,
  IP-conversation analysis, port-diversity analysis, per-window SYN/ACK
  flag counting) found `172.16.0.5` is the sole real attacker, running a
  sustained UDP flood against `192.168.50.1` throughout most of the
  capture and a SYN flood concentrated in chunk 4's tail files. Each
  `(src_ip, 0.5s window)` is labeled with a real attack TYPE from actual
  packet content — `udp` if UDP-dominant, `syn` if SYN-without-ACK-dominant,
  `benign` otherwise — not assumed from which file/chunk it came from. This
  matches CIC-DDoS2019's **"UDP"** and **"SYN"** attack categories. This is
  real traffic-content analysis, not a value taken from the thesis or the
  old fabricated code.
- **Attack categories NOT reproducible from this dataset:** the thesis's
  Table 7.4 claims TCP SYN Flood, UDP Amplification, HTTP POST Flood, and
  Slowloris (L7). This rebuild now covers 2 of those 4 (SYN Flood, and a
  generic UDP flood standing in for "UDP Amplification" — whether this
  attacker's UDP flood is specifically amplification-style, as opposed to
  a direct flood, was not separately investigated and remains an open
  item). The documented CIC-DDoS2019 attack list for both capture days
  (PortMap, NetBIOS, LDAP, MSSQL, UDP, UDP-Lag, SYN / NTP, DNS, LDAP,
  MSSQL, NetBIOS, SNMP, SSDP, UDP, UDP-Lag, WebDDoS, SYN, TFTP) contains no
  "Slowloris" and no category literally named "HTTP POST Flood" at all —
  a real mismatch between what the thesis claims to have evaluated and
  what this dataset actually contains, not something this rebuild can fix
  by trying harder.
- **Split methodology, a real documented deviation:** a naive single
  global temporal split ("first 80% of capture-time = train") would put
  almost all real SYN examples in the test set and none in training,
  since SYN data is concentrated in the last few files of the whole
  capture. Instead each attack type (benign/udp/syn) is split 80/20 by
  time *within that type*, then combined — still chronological within
  each type, just applied per-type so both real attack types are
  genuinely represented in both splits. See
  `controller/ml/train_model.py`'s `per_type_temporal_split`.

## Thrift vs. gRPC/P4Runtime — a real, documented substitution

The thesis text (§7.6) describes a gRPC/P4Runtime control plane
(`p4runtime-sh`). This repo's BMv2 was built with `-DWITH_PI=OFF`, meaning
it exposes **Thrift RPC** (the same protocol `simple_switch_CLI` uses),
not gRPC/P4Runtime. This was a deliberate choice given this machine's
8GB-RAM constraint (building `p4lang/PI` for true P4Runtime is a
substantially heavier dependency chain) — documented here rather than
left as a silent mismatch between what's built and what the thesis
describes. **The thesis's methodology section should be updated to
describe Thrift-CLI, not gRPC/P4Runtime, if this build is what the
chapter now cites.**

## Traffic replay: tcpreplay, not TRex

The thesis describes TRex (DPDK, nanosecond-precision inter-arrival
timing) for traffic replay. TRex requires DPDK-capable networking, which
isn't available in this WSL2 virtualized-networking environment. Real
CIC-DDoS2019 pcaps are replayed instead via `tcpreplay`. One real,
measured finding from this substitution: a fixed-rate replay
(`--pps=200`) distorts the timing-based features enough to misclassify
the real attacker as benign (1.7% malicious probability); replaying with
the pcap's **real original inter-packet timing** (`--multiplier=1.0`)
correctly classifies it (77.4%). All real latency trials use
`--multiplier=1.0` for this reason — see `scripts/run_latency_trials.sh`.

## Known issues fixed during this rebuild

- `p4/p4_xgboost.p4` had 3 real compile errors (not simulated bugs — this
  file was previously "reference only, not compiled" per the prior
  README): `MyDeparser` was declared `parser` but used `control`-block
  syntax; a custom `standard_metadata_t` struct duplicated v1model.p4's
  own built-in one; `HashAlgorithm_t` doesn't exist in this p4c version's
  v1model.p4 (it's `HashAlgorithm`). All fixed, verified compiling and
  loading into a real `simple_switch`.
- `baseline/baseline_reimpl/extract_features.py` had a real pandas
  groupby-column-exclusion bug (modern pandas excludes groupby key columns
  from the sub-frame passed to `.apply()`) affecting both `protocol` and
  `dst_port` access, plus a real CSV round-trip bug (`pkt_lengths` written
  as a Python list's string repr, read back as a plain string). Fixed in
  `common.py` and `extract_features.py`.
- `baseline/baseline_reimpl/evaluate_baselines.py` hardcoded
  accuracy/precision/recall/FPR for the P4-XGBoost comparison row to the
  thesis's original numbers regardless of what `--p4xgboost-f1` was
  passed — only F1 was actually parameterized. Fixed to require all real
  values explicitly via CLI flags, no fallback to fabricated numbers.
- `tests/test_model.py::test_xgboost_malicious` used a hand-picked
  synthetic feature vector (`pkt_rate=1200`) tuned to trigger the old fake
  model's `if pkt_rate > 500` rule. The real trained model correctly
  doesn't recognize it (this real attacker sends a sustained moderate
  rate, not an extreme burst) — the test encoded an assumption from the
  fabricated model, not real behavior. Fixed to pull real labeled rows
  from `evaluation_output/extracted_features.csv` instead of a synthetic
  vector; all 4 tests pass against the real pipeline.
- **tshark boolean flag parsing** (`controller/ml/train_model.py` and,
  originally, `baseline/baseline_reimpl/build_real_dataset.py`): `tshark`
  exports `tcp.flags.syn`/`tcp.flags.ack` as the literal text `"True"` /
  `"False"`, not `"1"`/`"0"`. `pd.to_numeric(errors="coerce").fillna(0)`
  silently coerced every value to `0`, zeroing all real SYN/ACK flag data.
  Found because a sanity check ("why did you not look for SYN attack
  type?") turned up `max syn_count: 0` across thousands of real TCP
  flows — physically impossible for real traffic. Fixed via
  `.fillna("False").isin(["True", "1", "1.0"]).astype(int)`.
- **OOM building a combined real-packets CSV**
  (`baseline/baseline_reimpl/build_real_dataset.py`): an earlier version
  concatenated all 180 files' raw packets (62.7M rows) into one DataFrame
  before writing `real_packets.csv`, crashing with
  `OSError: [Errno 12] Cannot allocate memory` on this 8GB-RAM machine. No
  data was lost (every file's raw packets were already safely cached
  per-file). Fixed by aggregating each file straight to flow-level rows
  immediately after extraction and never holding more than one file's raw
  packets in memory at once — the combined `real_packets.csv` is no longer
  produced at all, only the much smaller `real_flows.csv`.
- **30+ minute per-file aggregation**
  (`baseline/baseline_reimpl/extract_features.py`): `from_packets()`
  originally called `groupby(...).apply(python_function)` — a per-group
  Python call that, on a large real UDP-flood file with tens of thousands
  of distinct 5-tuple flows, ran over 30 minutes with no completion in
  sight (confirmed hung via `ps aux`, not just slow). Rewritten to
  vectorized pandas `.agg()` for every field except the inherently
  list-shaped `pkt_lengths` column; the same file dropped to 2.24 seconds
  with identical output (verified: same 40,055 flows, same
  benign/udp/syn split).

## Repository Structure

- `p4/p4_xgboost.p4`: The real P4-16 data-plane pipeline. Compiles with
  `p4c-bm2-ss` and runs on a real `simple_switch` (see "Known issues
  fixed").
- `p4/p4_xgboost.json`: The compiled BMv2 JSON, loadable by `simple_switch`.
- `controller/app.py`: Real SDN controller — a real scapy sniffer /
  digest listener, real feature extraction, real XGBoost inference, real
  Thrift drop-rule installation. `--duration`/`--interfaces` CLI flags for
  live operation.
- `controller/core/features.py`: Real per-source-IP sliding-window 10-D
  feature computation, Redis-backed.
- `controller/core/metrics.py`: Latency/accuracy bookkeeping, unchanged
  in interface, now fed real data.
- `controller/ml/train_model.py`: Real offline pipeline — caches raw
  per-packet tshark exports (`evaluation_output/raw_packet_cache/`,
  window-size-independent, so re-aggregating at a different window or with
  different features never needs to re-run tshark), aggregates real 10-D
  features, trains and saves the real XGBoost model, runs the real
  per-attack-type temporal 80/20 evaluation.
  `controller/ml/xgboost_model.py`: Loads that real trained model artifact.
- `controller/p4/p4runtime.py`: Real Thrift RPC client (see "Thrift vs.
  gRPC/P4Runtime" above).
- `controller/p4/digest_listener.py`: Real digest-notification listener.
- `baseline/baseline_reimpl/`: Functional re-creations of
  Jaqen/POSEIDON/FlowLens (Stage-2/Option-A scope — see its own README),
  now wired to the same real dataset via `build_real_dataset.py` for a
  real Table 7.6.
- `scripts/setup_topology.sh`: Real `ip netns`/veth topology + real
  `simple_switch` startup + real Thrift table population (direct veth
  approach, not Mininet's Python API — see script comments for why).
- `scripts/run_latency_trials.sh`: Real independent latency trials (fresh
  switch state each trial, since the bloom-dedup design means one digest
  per source IP per switch lifetime). Re-run against the combined UDP+SYN
  model for this update.
- `scripts/run_live_measurement.sh`: Single live-run helper.
- `scripts/scan_wider_attack_types.sh`: Forensic scan used to locate the
  real SYN flood in chunk 4's tail files.
- `scripts/ablation_feature_dims.py` / `ablation_tree_depth.py` /
  `ablation_register_width.py`: Real ablation studies, each re-run against
  the combined UDP+SYN 83,457-row dataset via the same per-type temporal
  split as the main training run. **Stale** relative to the current
  10-feature/depth=9 production model — see "Real results vs. thesis
  claims" above.
- `scripts/tune_model_search.py`: Real leakage-safe hyperparameter search
  (3-fold CV on the training split only) that found the current
  `max_depth=9, learning_rate=0.2`.
- `scripts/feature_engineering_sweep.py`: Real test of adding
  `syn_noack_ratio`/`ack_ratio` at the same 0.5s window — found the real
  83.46%→86.22% accuracy improvement adopted into production.
- `scripts/window_sweep.py`: Real window-size sweep (0.1s–4.0s) using a
  cached raw-packet dataset for fast re-aggregation without re-running
  tshark per window size.
- `scripts/flowlens_window_sweep.py`, `scripts/all_baselines_windowed.py`,
  `scripts/baselines_tuned.py`: Real re-evaluation of all three baselines
  (Jaqen-lite, POSEIDON-lite, FlowLens-lite) at the same 0.5s window as
  P4-XGBoost, including fair threshold retuning for the two rule-based
  baselines — the honest, apples-to-apples Table 7.6.
- `evaluation/summary.py`: Regenerates `evaluation_output/summary.json`
  (v3) from real computed results (`train_eval_preview.json`,
  `latency_trials.json`, `ablations.json`, the windowed baseline
  comparison, the feature/hyperparameter/window-size research) — no more
  static fabricated data.
- `evaluation_output/`: Real computed outputs — `extracted_features.csv`
  (real 10-D feature rows, 83,457 window-rows across benign/udp/syn),
  `raw_packet_cache/` (window-size-independent per-file raw packet cache —
  the real resumability + fast-re-aggregation mechanism), `train_eval_preview.json`
  (real confusion matrix + overall and per-attack-type classification
  reports, current 10-feature/depth=9 model), `latency_trials.json` (15
  real trials, **stale** — see caveat above), `ablations.json` (5 real
  re-run/kept ablations, **stale** — see caveat above),
  `feature_engineering_results.json`, `tuning_search_results.json`,
  `window_sweep_results.json`, `all_baselines_windowed.json`,
  `baselines_tuned_windowed.json` (the real accuracy-improvement and
  apples-to-apples baseline research), `summary.json` (real aggregate of
  all of the above).
- `config/settings.yaml`: ML hyperparameters (unchanged — 100 estimators,
  depth 6, lr 0.1 — now actually used by a real `xgboost.XGBClassifier`).

## Getting Started (real pipeline)

### Prerequisites

- WSL2 Ubuntu (native Windows cannot run BMv2/p4c/Mininet-equivalent
  networking).
- BMv2 (`simple_switch`, `simple_switch_CLI`) and `p4c` built from source
  — see the build tracker for the exact dependency list and any
  version-specific fixes needed (this was built against Ubuntu 26.04 /
  gcc 15.2; adjust for your distro).
- Python venv at `.venv/` (gitignored) with `redis xgboost scikit-learn
  pandas pyyaml matplotlib scapy thrift` installed — see
  `requirements.txt`.
- `redis-server` running.
- The real CIC-DDoS2019 pcap sample (not included in this repo — see
  "Dataset scope" above for where to get it).

### 1. Build the topology and start the switch

```bash
bash scripts/setup_topology.sh
```

### 2. Compile the P4 program (if not already compiled)

```bash
cd p4 && p4c-bm2-ss --std p4-16 -o p4_xgboost.json p4_xgboost.p4
```

### 3. Train the real model (if `controller/ml/model.json` doesn't exist)

```bash
.venv/bin/python -m controller.ml.train_model
```

Extracts and caches all 180 target files (~50 minutes on first run,
resumable via `evaluation_output/extraction_cache/` if interrupted — a
full host shutdown kills the WSL2 VM, so cached files let a re-run skip
what's already done), then trains and saves the combined UDP+SYN model.

### 3b. Re-run ablations (optional, only after retraining on new data)

```bash
.venv/bin/python scripts/ablation_feature_dims.py
.venv/bin/python scripts/ablation_tree_depth.py
.venv/bin/python scripts/ablation_register_width.py
```

### 4. Run the real live controller

```bash
.venv/bin/python -m controller.app --duration 90 --interfaces veth-h1-br,veth-h2-br
```

### 5. Run real latency trials

```bash
bash scripts/run_latency_trials.sh 15
```

### 6. Regenerate the real evaluation summary

```bash
.venv/bin/python -m evaluation.summary
```

### 7. Run the tests

```bash
.venv/bin/python -m pytest tests/ -v
```

## Citation

Smriti Arora, Hari Babu K, Samiksha Kaul, "P4-XGBoost: High-Speed Hybrid DDoS
Defense," Journal of Network and Computer Applications, Elsevier (in preparation).
