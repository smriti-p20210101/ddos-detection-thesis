# Ch.3 — Entropy-based P4 detection
# Builds a P4 dev environment: p4c + BMv2 (simple_switch) + Mininet, via the
# official P4 tutorials installer. First build is slow (~20-30 min, mostly
# compiling p4c/BMv2 from source) — this is expected, not a hang.
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
LABEL description="Ch.3 entropy-based DDoS detection in P4 (thesis: ddos-detection-thesis)"

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip sudo build-essential make iproute2 net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/p4lang/tutorials.git /opt/p4-tutorials \
    && cd /opt/p4-tutorials && ./install.sh

# Fail the build fast if the toolchain didn't actually install, rather than
# failing confusingly later at `make` or `run.sh` time.
RUN p4c --version && simple_switch --help > /dev/null && mn --version

WORKDIR /workspace
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .

# Compile at image-build time so the container is ready to run immediately:
RUN make

# Mininet/veth setup needs to create virtual interfaces — run with:
#   docker run --privileged ch3-entropy-p4
CMD ["/bin/bash"]
