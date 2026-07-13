# Ch.5 — Decentralised gossip at scale
# NOTE: the large-scale (150-switch) sweep in evaluation/scalability.py is
# CPU/RAM heavy — pass `--cpus=8 --memory=16g` (or your host's equivalent)
# to `docker run` for that specific run.
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
LABEL description="Ch.5 decentralised gossip at scale (thesis: ddos-detection-thesis)"

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip sudo build-essential iproute2 \
    && rm -rf /var/lib/apt/lists/*

# P4 toolchain (p4c + BMv2) — per this chapter's own README, p4app is also
# a supported route; the tutorials installer below is the more reproducible
# from-source path and is consistent with Ch.3/4's setup.
RUN git clone https://github.com/p4lang/tutorials.git /opt/p4-tutorials \
    && cd /opt/p4-tutorials && ./install.sh
RUN p4c --version && simple_switch --help > /dev/null

WORKDIR /workspace
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .

VOLUME ["/workspace/data"]
CMD ["/bin/bash"]
