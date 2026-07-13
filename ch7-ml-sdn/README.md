# Ch.7 — Machine Learning-Assisted DDoS Detection in SDN: Latency Decomposition

Measures and decomposes end-to-end SDN-based ML detection time into (a)
controller <-> switch communication delay and (b) ML inference time, using a
Ryu controller + Decision Tree classifier. Corresponds to the ICOIN 2025
paper, "Assessing the Impact of Machine Learning-Based DDoS Attack Detection
on SDN Network Performance."

## Suggested new layout for this chapter

This chapter currently has no folder structure at all — just loose files at
the top level, plus a README saved with the wrong extension
(`README.md.txt`, which GitHub won't render as a README). Proposed
reorganisation (minimal-risk — no code edits required, see note below):

```
ch7-ml-sdn/
├── controller/
│   ├── switch.py               # base Ryu L2 switch (SimpleSwitch13)
│   ├── DT_controller.py         # SimpleMonitor13(switch.SimpleSwitch13): flow-stats
│   │                             # polling + Decision Tree prediction
│   ├── trained_model.pkl         # legacy/comparison model — DT_controller.py does
│   │                              # NOT load this one; verify before deleting
│   └── trained_model_new.pkl      # the model DT_controller.py actually loads
├── README.md                      # this file (replaces README.md.txt)
└── requirements.txt
```

**Why keep the `.pkl` files alongside the controller scripts, not in a
separate `models/` folder**: `DT_controller.py` loads its model with a
hardcoded relative path —
```python
model = pickle.load(open("trained_model_new.pkl", 'rb'))
```
This is relative to whatever directory you're in when you launch
`ryu-manager`, not to the script's own location. Keeping the `.pkl` files in
the same folder as `DT_controller.py`, and running commands from inside
`controller/`, means this works with **zero code changes**. If you'd rather
move the model elsewhere, update that one line to a proper path first.

**To apply this layout**: create the `controller/` folder and move
`switch.py`, `DT_controller.py`, `trained_model.pkl`, and
`trained_model_new.pkl` into it (see the top-level `CLEANUP_GUIDE.md` for how
to do renames/moves via the GitHub web UI). Then delete `README.md.txt` after
uploading this file.

## What this experiment shows

This chapter asks where SDN-based ML detection actually spends its time: the
ML model, or the network round-trip to get flow statistics to the
controller. The result: communication delay dominates by roughly 20x under
load, motivating the hybrid architecture in Ch.8.

## Architecture

```
 h1 (attacker, hping3) --- switch (Mininet/OVS, running switch.py's OpenFlow app) --- h2 (victim)
                                |  FlowStatsRequest / FlowStatsReply
                                v
                    Ryu controller running DT_controller.py
                       -> loads trained_model_new.pkl
                       -> DecisionTreeClassifier.predict() per flow
                       -> result: 0 (safe) / 1 (ddos)
```

- `switch.py` defines `SimpleSwitch13`, a bare-bones Ryu OpenFlow 1.3 L2
  learning switch (MAC-address forwarding table, no ML).
- `DT_controller.py` defines `SimpleMonitor13(switch.SimpleSwitch13)`, which
  adds periodic flow-stats polling (`hub.spawn(self._monitor)`) and feeds
  the collected stats into the pre-trained Decision Tree.

## Requirements

**Hardware**: 2 vCPUs / 2GB RAM is enough — this is a small, 1-switch
topology; timing measurements are sensitive to host CPU contention though
(see Troubleshooting).

**Software**: Ryu, Open vSwitch, Mininet, `hping3`, plus `requirements.txt`.

## Setup

```bash
pip install -r requirements.txt
sudo apt install mininet openvswitch-switch hping3
```

**Verify before running anything:**
```bash
ryu-manager --version
sudo ovs-vsctl --version
```

## Running

```bash
cd controller   # important: trained_model_new.pkl is loaded via a relative path
ryu-manager DT_controller.py
```
Then, in a separate Mininet setup, run a topology (attacker + victim host
connected to one OpenFlow switch) and drive traffic with `hping3` — both
fast (`--interval u10000`, rate-limited) and flood (`--flood`) modes, per
the paper's methodology — while `DT_controller.py`'s console output reports
predictions per flow-stats poll.

## Expected output

- Fast attack: mean total detection time ≈ **0.22 s**.
- Flood attack: mean total detection time ≈ **4.75 s** (~21x degradation).
- Console output from `DT_controller.py` should show flow classifications
  (0/1) with occasional timing prints if you add instrumentation around the
  `_monitor` loop and the `predict()` call.

## Extending this chapter

- **Different classifier**: `trained_model_new.pkl` is a plain `pickle`-dumped
  scikit-learn object — retrain and re-pickle any compatible classifier, then
  point `DT_controller.py`'s `load_model()` at the new file.
- **Timing instrumentation**: the current code doesn't print explicit timing
  breakdowns — wrap the flow-stats request/reply and the `predict()` call
  each in a `time.time()` pair (see Ch.8's `controller/core/metrics.py` for
  a worked example of this pattern) if you want to reproduce the exact
  latency table from the paper rather than just the classification behaviour.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `FileNotFoundError: trained_model_new.pkl` | You ran `ryu-manager` from the wrong directory — `cd` into `controller/` first (see "Why keep the .pkl files alongside" above). |
| Timing numbers much higher than the paper's | Host CPU contention — rerun on a quieter host. |
| `ovs-vsctl: command not found` | Open vSwitch not installed/started. |

## Citation

Smriti Arora, HariBabu K, Shrinivas Choudhary, "Assessing the Impact of
Machine Learning-Based DDoS Attack Detection on SDN Network Performance,"
ICOIN 2025.
