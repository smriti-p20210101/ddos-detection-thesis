# Ch.6 — Cooperative MULTOPS (Click Modular Router)
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
LABEL description="Ch.6 cooperative MULTOPS via Click Modular Router (thesis: ddos-detection-thesis)"

RUN apt-get update && apt-get install -y \
    git build-essential python3 python3-pip telnet iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/kohler/click.git /opt/click \
    && cd /opt/click && ./configure --enable-user-multithread && make -j$(nproc) && make install

WORKDIR /workspace
COPY click-elements/IPRateMonitor.cc click-elements/IPRateMonitor.hh /opt/click/elements/
COPY click-elements/PolicyEnforcer.cc click-elements/PolicyEnforcer.hh /opt/click/elements/
RUN cd /opt/click && ./configure --enable-user-multithread && make -j$(nproc) && make install
RUN click --version

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .

# Run with: docker run --network host <image>
CMD ["/bin/bash"]
