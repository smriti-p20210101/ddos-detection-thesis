#!/bin/bash
# Real end-to-end measurement run: fresh topology -> live controller
# (real packet sniffer + real digest listener + real feature extraction +
# real XGBoost + real Thrift drop-rule install) -> real attack pcap replay
# via tcpreplay -> real per-stage latency export.
set -e
cd "$(dirname "$0")/.."

echo "[run] resetting topology to a clean state..."
bash scripts/setup_topology.sh
sudo chmod 666 /tmp/bmv2-0-notifications.ipc

echo "[run] starting live controller in background (90s window)..."
sudo setsid nohup .venv/bin/python -u -m controller.app \
  --duration 90 --interfaces veth-h1-br,veth-h2-br \
  > /tmp/controller_run.log 2>&1 < /dev/null &
disown
echo "[run] waiting for real controller startup (xgboost import alone takes ~18s from /mnt/c)..."
for wait_s in $(seq 1 40); do
  if grep -q "digest listener active" /tmp/controller_run.log 2>/dev/null; then
    echo "[run] controller ready after ${wait_s}s"
    break
  fi
  sleep 1
done
echo "[run] controller startup log:"
cat /tmp/controller_run.log

echo "[run] replaying real attack pcap (SAT-01-12-2018_0, real attacker 172.16.0.5) at pps=5000..."
sudo tcpreplay --intf1=veth-h1-br --pps=5000 --loop=1 "/mnt/d/Smriti PhD/extracted_sample/SAT-01-12-2018_0"

echo "[run] replay done, waiting for controller's window to finish (remaining digests to process)..."
sleep 30

echo "[run] === controller log ==="
cat /tmp/controller_run.log

echo "[run] === exported metrics ==="
cat evaluation_output/controller_metrics.json 2>&1

echo "[run] === per-stage real latency timings (first 10) ==="
python3 -c "
import json
data = json.load(open('evaluation_output/stage_timings.json'))
print(f'{len(data)} total real digest events')
for row in data[:10]:
    print(row)
"
