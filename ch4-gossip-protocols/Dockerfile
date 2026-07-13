# Ch.4 — Gossip protocol comparison in P4 (probability-based, as currently
# checked in — see README.md for what would need to change to also
# reproduce the epidemic variant).
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
LABEL description="Ch.4 gossip-based threat dissemination in P4 (thesis: ddos-detection-thesis)"

RUN apt-get update && apt-get install -y \
    git curl python3 python3-pip sudo build-essential make iproute2 net-tools \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/p4lang/tutorials.git /opt/p4-tutorials \
    && cd /opt/p4-tutorials && ./install.sh
RUN p4c --version && simple_switch --help > /dev/null

WORKDIR /workspace
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY ddosd-p4/ ddosd-p4/

WORKDIR /workspace/ddosd-p4
RUN make

# Requires: docker run --privileged (Mininet/veth interface creation)
CMD ["/bin/bash"]
