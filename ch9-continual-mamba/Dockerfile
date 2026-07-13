# Ch.9 — Continual Mamba+KAN+EWC
# GPU build: uses the official PyTorch CUDA 12.1 base image so torch and
# CUDA are correctly paired (installing torch==2.3.1 via plain pip resolves
# to a CPU-only wheel, which silently makes training much slower with no
# error — this base image avoids that trap entirely).
FROM pytorch/pytorch:2.3.1-cuda12.1-cudnn8-runtime
LABEL description="Ch.9 continual Mamba+KAN+EWC for IoT IDS (thesis: ddos-detection-thesis)"

WORKDIR /workspace
COPY requirements.txt .
# torch is already provided (correctly, with CUDA) by the base image —
# strip it here so pip doesn't try to reinstall the CPU-only PyPI wheel.
RUN grep -v "^torch" requirements.txt > requirements.nocuda.txt \
    && pip install --no-cache-dir -r requirements.nocuda.txt
COPY . .

RUN python3 -c "import torch; print('torch', torch.__version__, 'CUDA available:', torch.cuda.is_available())"
# No setup.py/pyproject.toml in this repo — scripts/*.py already insert
# src/ onto sys.path themselves (see scripts/run_experiment.py), so no
# package install step is needed here; just run scripts from the repo root.

CMD ["/bin/bash"]
