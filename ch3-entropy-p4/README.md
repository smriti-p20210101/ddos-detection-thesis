# Ch.3 — Entropy-Based DDoS Detection in the P4 Data Plane

Implements Shannon-entropy-based DDoS detection first on the SDN **control plane**
(Python controller, single switch) and then natively **in the data plane** using
P4, with EWMA/EWMD adaptive thresholding and a Count-Min Sketch for frequency
estimation. Corresponds to the LCN 2023 paper (DOI: 10.1109/LCN58197.2023.10223404).

## Architecture

```
                  +---------------------------+
 traffic -------> |  Gateway BMv2 switch (P4) |--> forwarded / dropped
 (Mininet hosts)  |  - Count-Min Sketch (d=4) |
                  |  - EWMA(H), EWMD(H)       |
                  |  - Gossip to internal     |
                  |    switches (freq=16)     |
                  +---------------------------+
```

- **Entropy metric**: Shannon entropy `H = log2(m) - (1/m) * sum(f_i log2(f_i))`
  over source/destination IP distributions, sampled per observation window.
- **Count-Min Sketch**: depth `d = 4`, used to estimate per-flow packet frequency
  under register-array constraints (no per-flow state).
- **Adaptive thresholding**: exponentially weighted moving average `M` (weight
  `alpha = 0.125`) and moving difference `D`, with confidence parameter
  `beta = 2.5`. Attack flagged when `H > M + beta*D` (source) or
  `H < M - beta*D` (destination).
- **In-band telemetry + gossip**: entropy updates are piggybacked on a custom
  header and gossiped to internal switches at frequency 16 so switches off the
  packet's path still learn about the anomaly.
- **Training period**: first 20 observation windows are used to warm up `M`/`D`
  before detection is enabled.

## Repository contents

```
ch3-entropy-p4/
├── control_plane/        # Python control-plane prototype (single switch, 4 hosts)
├── data_plane/
│   ├── entropy.p4         # P4 program: parser, CMS registers, EWMA/EWMD, gossip
│   └── topology.py        # Mininet topology (gateway + internal switches)
├── scripts/
│   ├── run_experiment.sh  # Brings up Mininet + BMv2, replays traffic, logs entropy
│   └── plot_entropy.py    # Reproduces the entropy-vs-time / EWMA/EWMD figures
├── requirements.txt
└── Dockerfile
```

## Setup

### Option A — Docker (recommended)
```bash
docker build -t ch3-entropy-p4 .
docker run --rm -it --privileged ch3-entropy-p4
```
`--privileged` is required because Mininet creates virtual network interfaces.

### Option B — Local install
1. Install a P4 toolchain: `p4c` compiler + BMv2 (`simple_switch`). Easiest path is
   the official P4 tutorials installer: https://github.com/p4lang/tutorials
   (`sudo ./install.sh` from that repo, or use their Vagrant/VM image).
2. Install Mininet: `sudo apt install mininet` (or via the same P4 tutorials setup,
   which installs a compatible version).
3. `pip install -r requirements.txt`

## Running

```bash
cd data_plane
p4c --target bmv2 --arch v1model -o build entropy.p4
sudo python3 topology.py          # starts Mininet + simple_switch instances
sudo bash ../scripts/run_experiment.sh
python3 ../scripts/plot_entropy.py --log logs/entropy.csv
```

## Expected output
- Entropy trace showing decline toward 0 under simulated SYN-flood conditions.
- Attack flagged within 2 observation windows of the flood starting.
- Control-plane baseline (for comparison) in `control_plane/` reproduces the
  0.22 s / 4.75 s figures used as the Ch.7 baseline.

## Datasets / traffic
No external dataset required — traffic is synthetically generated in Mininet using
`hping3` / `netcat` for the attack phase and idle background traffic otherwise.

## Citation
Smriti, K. HariBabu, L. Kumaar, and Rahul Kumar, "Early Detection of DDoS Attacks
in Networks Leveraging Data Plane Programming," 2023 IEEE 48th LCN.
