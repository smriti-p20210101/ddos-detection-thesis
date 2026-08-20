# Ch.7 P4-XGBoost -- real BMv2 + p4c + Redis + XGBoost pipeline.
#
# NOT TEST-BUILT: no Docker was available in the environment this Dockerfile
# was written in, so `docker build` has not actually been run against it.
# Every individual command below is drawn from the exact steps that were
# validated working (in WSL2 Ubuntu 26.04) while building this chapter's
# real pipeline -- but the Dockerfile itself, as a whole, needs a real
# `docker build` + `docker run` pass to confirm before relying on it.
#
# Requires --privileged (or at minimum --cap-add=NET_ADMIN --cap-add=NET_RAW)
# at `docker run` time: the real pipeline creates network namespaces and
# veth pairs (scripts/setup_topology.sh) and runs simple_switch/tcpreplay,
# all of which need elevated networking privileges a default container
# doesn't have.

FROM ubuntu:26.04
LABEL description="Ch.7 P4-XGBoost -- real BMv2/p4c/Redis/XGBoost pipeline (thesis: ddos-detection-thesis)"
ENV DEBIAN_FRONTEND=noninteractive

# --- BMv2 + p4c build dependencies -----------------------------------------
# This exact list is what actually got a clean build in this chapter's real
# rebuild (Ubuntu 26.04) -- several of these (libjsoncpp-dev, libxxhash-dev,
# nlohmann-json3-dev, libspdlog-dev, python3-thrift) surfaced only as
# sequential "missing package" errors during that real build, not from any
# single upstream doc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool cmake pkg-config \
    libboost-dev libboost-system-dev libboost-filesystem-dev \
    libboost-thread-dev libboost-program-options-dev libboost-test-dev \
    libboost-graph-dev libboost-iostreams-dev \
    libssl-dev libpcap-dev libjudy-dev \
    libgmp-dev flex bison libfl-dev \
    protobuf-compiler protobuf-compiler-grpc libprotobuf-dev \
    libgrpc++-dev libgrpc-dev \
    libthrift-dev thrift-compiler python3-thrift \
    python3-dev python3-pip python3-venv \
    libnanomsg-dev \
    libjsoncpp-dev nlohmann-json3-dev libspdlog-dev libxxhash-dev \
    tshark redis-server \
    git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- BMv2 (behavioral-model), WITH_PI=OFF (real Thrift control plane, ------
# see README.md's "Thrift vs. gRPC/P4Runtime" section for why) --------------
WORKDIR /opt/build
RUN git clone --recursive https://github.com/p4lang/behavioral-model.git \
    && cd behavioral-model && mkdir build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DWITH_THRIFT=ON -DWITH_PI=OFF \
                -DWITH_STRESS_TESTS=OFF -DENABLE_WERROR=OFF \
    && make -j"$(nproc)" \
    && make install && ldconfig

# --- p4c ---------------------------------------------------------------
RUN git clone --recursive https://github.com/p4lang/p4c.git \
    && cd p4c && mkdir build && cd build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release \
    && make -j"$(nproc)" \
    && make install

# --- Repo + real Python dependencies ----------------------------------------
WORKDIR /workspace
COPY requirements.txt .
RUN python3 -m venv .venv && .venv/bin/pip install --upgrade pip \
    && .venv/bin/pip install -r requirements.txt

COPY . .

# Compile the real P4 program at image-build time as a sanity check --
# fails the build if p4/p4_xgboost.p4 doesn't actually compile.
RUN cd p4 && /usr/local/bin/p4c-bm2-ss --std p4-16 -o p4_xgboost.json p4_xgboost.p4

# Real test suite (needs a trained model + extracted features present in
# the build context, e.g. via evaluation_output/ and controller/ml/model.json
# -- these are real derived data, not included in the image by default per
# .gitignore; mount or regenerate them before running this stage if absent).
# Not run at build time here since it depends on that real data being
# present, unlike the P4 compile check above which only needs the repo code.

CMD ["/bin/bash"]
