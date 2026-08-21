#!/bin/bash
# Real digest-payload-size ablation: for each of the 3 real compiled
# variants (baseline 6B, padded ~100B, padded ~1500B -- see
# scripts/digest_payload_ablation.p4), reset the topology, load that
# variant, start the real listener, replay the real attacker trigger
# slice, and record the real time-to-digest-receipt and real message size.
#
# Run this AFTER any other live-switch work (e.g. the latency trials) has
# finished -- it resets the topology and would collide with a concurrent
# live trial.
set -e
cd "$(dirname "$0")/.."

VARIANTS=(
  "scripts/digest_ablation_baseline.json:baseline_6B"
  "scripts/digest_ablation_100b.json:padded_100B"
  "scripts/digest_ablation_1500b.json:padded_1500B"
)

RESULTS_DIR="/tmp/digest_payload_ablation"
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

for entry in "${VARIANTS[@]}"; do
  json_path="${entry%%:*}"
  label="${entry##*:}"

  echo "=== [$label] resetting topology, loading $json_path ==="
  bash scripts/setup_topology_custom.sh "$(pwd)/$json_path" > /tmp/topo_reset_${label}.log 2>&1
  sudo chmod 666 /tmp/bmv2-0-notifications.ipc

  echo "=== [$label] starting real listener in background ==="
  sudo setsid nohup .venv/bin/python scripts/measure_digest_payload_latency.py \
    --label "$label" --out "$RESULTS_DIR/${label}.json" --timeout 60 \
    > "/tmp/measure_${label}.log" 2>&1 < /dev/null &
  disown
  sleep 1

  echo "=== [$label] replaying real attacker trigger slice ==="
  sudo tcpreplay --intf1=veth-h1-br --multiplier=1.0 --loop=1 \
    "/mnt/d/Smriti PhD/extracted_sample/attacker_trigger_slice.pcap" > /tmp/replay_${label}.log 2>&1

  echo "=== [$label] waiting for digest processing ==="
  sleep 6

  if [ -f "$RESULTS_DIR/${label}.json" ]; then
    echo "=== [$label] result: ==="
    cat "$RESULTS_DIR/${label}.json"
  else
    echo "=== [$label] WARNING: no result file produced ==="
    echo "--- listener log ---"
    cat "/tmp/measure_${label}.log" 2>/dev/null || true
  fi
  echo
done

echo "=== all 3 variants done -- combined results ==="
python3 -c "
import json, glob
for f in sorted(glob.glob('$RESULTS_DIR/*.json')):
    print(open(f).read())
"
