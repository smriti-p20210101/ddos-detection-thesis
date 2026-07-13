# Ch.4 — Gossip Protocol-Based Threat Dissemination (Epidemic vs. Probability-Based)

Compares two gossip dissemination strategies for spreading entropy-based DDoS
alerts natively in P4. Corresponds to the AINA 2025 paper, "DDoS Attack
Detection in Data Plane" (DOI: 10.1007/978-3-031-82838-6_11).

This chapter builds directly on Ch.3's `ddosd.p4` (same entropy/EWMA/EWMMD
core), adding randomised gossip dissemination on top.

## Repository contents (as they actually exist in this repo)

The real code lives one level deeper, in `ddosd-p4/` — the chapter directory
itself only holds a top-level `Dockerfile` and `requirements.txt`:

```
ch4-gossip-protocols/
├── Dockerfile
├── requirements.txt
└── ddosd-p4/
    ├── src/
    │   ├── ddosd.p4        # Ch.3's ddosd.p4 + probability-based gossip (see below)
    │   ├── headers.p4
    │   └── parser.p4
    ├── scripts/
    │   ├── main.py           # updated pcap parser: reads src_entropy/dst_entropy/meta_alarm
    │   ├── traffic.py
    │   ├── veth.sh
    │   ├── run.sh
    │   └── control_rules.txt
    ├── Makefile
    └── LICENSE               # GPLv3, inherited from Ch.3's upstream source
```

## What actually changed vs. Ch.3's `ddosd.p4`

Diffing against Ch.3's version, the meaningful change is in the gossip
dissemination call:

```p4
// Ch.3 (fixed target):
clone3(CloneType.I2E, CPU_SESSION, { ... });

// Ch.4 (probability-based — picks 1 of up to 4 sessions at random):
bit<32> session;
random(session, 0, 3);
clone3(CloneType.I2E, session, { ... });
```

**This checked-in version implements the probability-based protocol.** To
reproduce the **epidemic** comparison point from the paper (broadcast to all
neighbours), change this block to issue one `clone3` per neighbour session
(sessions 0–3) instead of selecting one at random — the rest of the pipeline
(entropy calculation, EWMA/EWMMD thresholding, header format) is unchanged
between the two variants. Consider keeping both as separate `.p4` files
(e.g. `ddosd_epidemic.p4` / `ddosd_probability.p4`) once you make this change,
so both are reproducible side-by-side rather than one overwriting the other.

`scripts/main.py` here also differs from Ch.3's: it parses a **shorter**
header (`src_entropy`, `dst_entropy`, `meta_alarm` only, via a proper `scapy`
`Packet` subclass) rather than the full 9-field header Ch.3 uses — reflecting
that this chapter's analysis focuses on convergence behaviour, not the raw
EWMA/EWMMD internals. This file does **not** have the `_main_`/`__main__`
typo that Ch.3's has.

## Setup

### Docker (recommended)
```bash
docker build -t ch4-gossip .
docker run --rm -it --privileged ch4-gossip
```

### Local install
Same P4 toolchain as Ch.3 (`p4c` + BMv2 + Mininet) — see Ch.3's README for
the install steps; nothing chapter-specific is needed beyond that.

## Running

```bash
cd ddosd-p4
make
sudo bash scripts/veth.sh
sudo bash scripts/run.sh
bash scripts/traffic.py
python3 scripts/main.py   # parses captured src_entropy/dst_entropy/meta_alarm
```

## Expected output

- Destination entropy declining under simulated attack, with the
  probability-based protocol converging more slowly than a full-broadcast
  (epidemic) implementation would — see the paper's Fig. 2/3 for the
  reference comparison.
- F1 = 0.935 for the better-performing configuration on this topology.

## Datasets / traffic

Synthetic traffic only, via `scripts/traffic.py`.

## Citation

Smriti, K. HariBabu, S. Garg, "DDoS Attack Detection in Data Plane," in
Advanced Information Networking and Applications (AINA 2025), L. Barolli (Ed.),
Lecture Notes on Data Engineering and Communications Technologies, vol. 252,
Springer, Cham, doi: 10.1007/978-3-031-82838-6_11.
