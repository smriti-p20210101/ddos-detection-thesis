# Ch.3 — Entropy-based P4 detection
# Base image bundles p4c + BMv2 (simple_switch) + Mininet, following the
# official P4 tutorials install script (https://github.com/p4lang/tutorials).
# NOTE: building p4c+bmv2 from source is slow (~20-30 min) on first build.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip sudo build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install the P4 toolchain (p4c, BMv2, Mininet) via the official installer.
# Pin to a known-good tag if you need reproducibility; HEAD is used here.
RUN git clone https://github.com/p4lang/tutorials.git /opt/p4-tutorials \
    && cd /opt/p4-tutorials \
    && ./install.sh || true   # some installer steps assume a desktop VM; verify manually if this fails

WORKDIR /workspace
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .

CMD ["/bin/bash"]
