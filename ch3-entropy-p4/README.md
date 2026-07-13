# Ch.3 — Entropy-Based DDoS Detection in the P4 Data Plane

Detects DDoS attacks by tracking Shannon entropy of source/destination IP
distributions natively in the P4 data plane, with EWMA/EWMD adaptive
thresholding. Corresponds to the LCN 2023 paper, "Early Detection of DDoS
Attacks in Networks Leveraging Data Plane Programming"
(DOI: 10.1109/LCN58197.2023.10223404).

The P4 data-plane logic (`src/ddosd.p4`) is adapted from Lapolli et al.'s
"Offloading Real-time DDoS Attack Detection to Programmable Data Planes"
(IM 2019), released under GPLv3 — see the licence header at the top of that
file and `LICENSE` in this directory.

## Repository contents (as they actually exist in this repo)

```
ch3-entropy-p4/
├── src/
│   ├── ddosd.p4        # main control block: CMS registers, EWMA/EWMD, alarm logic
│   ├── headers.p4       # ethernet/IPv4/ddosd_t header definitions
│   └── parser.p4        # parser state machine (ether_type 0x0800 / 0x6605 dispatch)
├── scripts/
│   ├── main.py           # parses captured ddosd_t headers out of a pcap (offline analysis)
│   ├── traffic.py         # traffic generation helper
│   ├── veth.sh              # sets up veth pairs for the topology
│   ├── run.sh                 # brings up BMv2 + loads the compiled P4 program
│   ├── control_rules.txt       # simple_switch_CLI table-entry script
│   ├── exp.pcap                 # sample capture used during development
│   └── first_offload.pcap        # sample capture used during development
├── Makefile
├── Dockerfile
├── LICENSE               # GPLv3 (inherited from the upstream ddosd.p4 source)
├── requirements.txt
└── .gitignore
```

## Known issue to fix in `scripts/main.py`

```python
if __name__ == "_main_":     # <- single underscores, never matches
    main()
```
This should be `if __name__ == "__main__":` (double underscores on both
sides). As written, running `python3 scripts/main.py` directly does nothing
— `main()` is defined but the guard never triggers. Fix this one-line typo
before relying on the script.

## Architecture

- **Header dispatch**: `parser.p4` checks EtherType — `0x0800` routes to
  ordinary IPv4 forwarding, `0x6605` routes to the custom `ddosd_t` header
  carrying entropy/EWMA/EWMD state between switches.
- **`ddosd_t` header fields** (see `headers.p4` and `scripts/main.py`'s
  mirrored `scapy` definition): `packet_num`, `src_entropy`, `src_ewma`,
  `src_ewmmd`, `dst_entropy`, `dst_ewma`, `dst_ewmmd`, `alarm`, `ether_type`.
- **Detection logic** (`src/ddosd.p4`): Count-Min Sketch-based frequency
  estimation feeding a Shannon entropy calculation, compared against an
  exponentially weighted moving average (EWMA) and moving mean difference
  (EWMMD) to flag anomalies — see the thesis Ch.3 text for the exact
  parameter values (`alpha`, `beta`, CMS depth) used in the evaluation.

## Setup

### Docker (recommended)
```bash
docker build -t ch3-entropy-p4 .
docker run --rm -it --privileged ch3-entropy-p4
```

### Local install
1. P4 toolchain: `p4c` + BMv2 (`simple_switch`) — via the official installer
   at https://github.com/p4lang/tutorials (`sudo ./install.sh`), or build
   `p4c`/`behavioral-model` from source yourself.
2. Mininet (installed alongside the P4 tutorials setup, or `sudo apt install mininet`).
3. `pip install -r requirements.txt`.

**Verify before running anything:**
```bash
p4c --version && simple_switch --help > /dev/null && sudo mn --version
```

## Running

```bash
make                       # compiles src/ddosd.p4 via the provided Makefile
sudo bash scripts/veth.sh   # sets up veth interfaces
sudo bash scripts/run.sh     # starts simple_switch with the compiled program,
                              # loads scripts/control_rules.txt via simple_switch_CLI
bash scripts/traffic.py       # generate benign + attack traffic (check the script's
                                # own --help for attack-phase flags)
python3 scripts/main.py         # offline analysis of a captured pcap's ddosd_t headers
                                  # (fix the "_main_" typo above first)
```
`scripts/exp.pcap` and `scripts/first_offload.pcap` are sample captures from
development — use them to sanity-check `scripts/main.py`'s parsing logic
without needing a live Mininet run first:
```bash
python3 scripts/main.py   # after fixing the typo, point it at exp.pcap first
```

## Expected output

- Entropy trace declining toward 0 under simulated attack conditions.
- The `alarm` field in the `ddosd_t` header flips to 1 once the EWMA/EWMD
  thresholds are crossed — this is the event `scripts/main.py` reports when
  parsing a capture.

## Datasets / traffic

No external dataset required — traffic is synthetically generated via
`scripts/traffic.py`.

## Citation

Smriti, K. HariBabu, L. Kumaar, and Rahul Kumar, "Early Detection of DDoS
Attacks in Networks Leveraging Data Plane Programming," 2023 IEEE 48th
Conference on Local Computer Networks (LCN), Daytona Beach, FL, USA, 2023,
pp. 1–4, doi: 10.1109/LCN58197.2023.10223404.

Data-plane detection logic adapted from: Â. C. Lapolli, J. A. Marques, and
L. P. Gaspary, "Offloading Real-Time DDoS Attack Detection to Programmable
Data Planes," IFIP/IEEE IM 2019.
