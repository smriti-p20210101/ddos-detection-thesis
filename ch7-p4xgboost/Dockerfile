# Ch.8 — P4-XGBoost replication package
# NOTE: the code in this directory is a pure-Python SIMULATION of the
# P4-XGBoost pipeline's control-plane logic and reproduces the paper's
# reported numbers/figures — it does not require a P4 toolchain, BMv2,
# Redis, or TRex to run. If you extend this into a live pipeline, you'll
# need a different, heavier image (see Ch.5's Dockerfile for the P4/BMv2
# pattern to adapt).
FROM python:3.10-slim
LABEL description="Ch.8 P4-XGBoost replication package (thesis: ddos-detection-thesis)"

WORKDIR /workspace
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN python3 -m pytest tests/ -q   # fail the build if the bundled tests don't pass

CMD ["/bin/bash"]
