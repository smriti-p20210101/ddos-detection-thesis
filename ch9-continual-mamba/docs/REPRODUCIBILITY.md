# Reproducibility Notes

## Main CIC-IoT2023 Reduced Protocol

```powershell
python .\scripts\run_experiment.py --config .\configs\bench_mamba_kan_noewc.json
python .\scripts\run_experiment.py --config .\configs\bench_mamba_kan_ewc5.json
python .\scripts\run_experiment.py --config .\configs\bench_mamba_mlp_noewc.json
python .\scripts\run_experiment.py --config .\configs\bench_mamba_mlp_ewc5.json
python .\scripts\run_experiment.py --config .\configs\bench_mlp_kan_noewc.json
python .\scripts\run_experiment.py --config .\configs\bench_mlp_kan_ewc5.json
```

## Multi-Seed Reduced Mamba+KAN Checks

```powershell
python .\scripts\run_benchmark.py --config .\configs\bench_mamba_kan_noewc.json --seeds 42 43 44 --output-dir .\outputs\ciciot_reduced_mamba_kan_noewc_3seed
python .\scripts\run_benchmark.py --config .\configs\bench_mamba_kan_ewc5.json --seeds 42 43 44 --output-dir .\outputs\ciciot_reduced_mamba_kan_ewc5_3seed
```

## Joint Upper Bound

```powershell
python .\scripts\run_joint_upper_bound.py --config .\configs\bench_mamba_kan_noewc.json --joint-epochs 12 --output-dir .\outputs\ciciot_reduced_mamba_kan_joint_upper_seed42
```

## ToN-IoT

```powershell
python .\scripts\run_experiment.py --config .\configs\exp_toniot_mamba_kan_noewc.json
python .\scripts\run_experiment.py --config .\configs\exp_toniot_mamba_kan_ewc02.json
python .\scripts\run_experiment.py --config .\configs\exp_toniot_mamba_kan_ewc1.json
python .\scripts\run_experiment.py --config .\configs\exp_toniot_mamba_kan_ewc5.json
```

## Static CIC-IDS2017

```powershell
python .\scripts\run_static_benchmark.py --config .\configs\static_cicids2017_local_full_mamba_kan.json
```

## Figure Regeneration

```powershell
python .\scripts\generate_toniot_figures.py
python .\scripts\generate_multitask_figures.py
```

## Current Scope

The repository includes implemented LwF, ER, ER-ACE-style, DER++-style, and joint upper-bound paths. Full-scale four- or five-task journal-grade runs for all stronger baselines remain future work unless new outputs are added.

