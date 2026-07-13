# Ch.4 — Gossip protocol comparison in P4 / Containernet
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip sudo build-essential docker.io wireshark-common tshark \
    && rm -rf /var/lib/apt/lists/*

# P4 toolchain (p4c + BMv2)
RUN git clone https://github.com/p4lang/tutorials.git /opt/p4-tutorials \
    && cd /opt/p4-tutorials && ./install.sh || true

# Containernet (Mininet + Docker-hosted nodes)
RUN git clone https://github.com/containernet/containernet.git /opt/containernet \
    && cd /opt/containernet && sudo ./install.sh || true

WORKDIR /workspace
COPY requirements.txt .
RUN pip3 install -r requirements.txt
COPY . .

CMD ["/bin/bash"]
