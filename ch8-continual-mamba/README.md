# Continual-Mamba for IoT Intrusion Detection

Author: Sarthak Bhagwan Ingle , Smriti Arora and Haribabu K 


This repository contains the code, configurations, selected result artifacts, figures, and preprint for a continual-learning intrusion detection study built around a compact Mamba-style selective state-space encoder and a KAN-inspired classifier head.

## What This Project Studies

IoT intrusion detection systems need to learn new attack families without forgetting previously learned traffic patterns. This project evaluates that problem under task-incremental IDS updates on CIC-IoT2023 and ToN-IoT, with an additional static CIC-IDS2017 comparison.

The central paper claim is protocol-focused:

> Active-class logit masking and bounded class weighting are necessary preconditions for valid continual IDS evaluation under task-incremental label drift.

The repository also reports EWC, replay/distillation code paths, multi-seed checks, a joint-training upper bound, and static/continual benchmark outputs.

## Repository Layout

```text
.
├── configs/                 # JSON experiment configurations
├── docs/                    # Dataset and reproduction notes
├── paper/
│   ├── preprint.pdf         # Updated preprint PDF
│   ├── main.tex             # Elsevier CAS double-column LaTeX source
│   └── figures/             # Figures used in the paper
├── results/
│   ├── ciciot2023/          # Main CIC-IoT2023 result summaries
│   ├── cicids2017_static/   # Static CIC-IDS2017 comparison artifacts
│   ├── multiseed/           # Multi-seed and smoke validation outputs
│   └── toniot/              # ToN-IoT result summaries
├── scripts/                 # Experiment, benchmark, static, and figure scripts
├── src/continual_mamba/     # Python package source
└── requirements.txt
```

## Install

Python 3.10 is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Example Runs

Run a single reduced-protocol experiment:

```powershell
python .\scripts\run_experiment.py --config .\configs\bench_mamba_kan_ewc5.json
```

Run the three-seed robustness checks:

```powershell
python .\scripts\run_benchmark.py --config .\configs\bench_mamba_kan_noewc.json --seeds 42 43 44 --output-dir .\outputs\ciciot_reduced_mamba_kan_noewc_3seed
python .\scripts\run_benchmark.py --config .\configs\bench_mamba_kan_ewc5.json --seeds 42 43 44 --output-dir .\outputs\ciciot_reduced_mamba_kan_ewc5_3seed
```

Run the joint-training upper bound:

```powershell
python .\scripts\run_joint_upper_bound.py --config .\configs\bench_mamba_kan_noewc.json --joint-epochs 12 --output-dir .\outputs\ciciot_reduced_mamba_kan_joint_upper_seed42
```

## Data

Datasets are not included because they are large. See [docs/DATASETS.md](docs/DATASETS.md) for expected paths and preparation notes.

## Notes

- PyTorch checkpoint files are intentionally excluded.
- Python virtual environments, caches, raw datasets, and generated zip packages are excluded.
- The included result files are selected artifacts needed to inspect the reported paper tables and figures.

