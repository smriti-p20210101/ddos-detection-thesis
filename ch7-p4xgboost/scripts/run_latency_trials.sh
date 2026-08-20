#!/bin/bash
# Real independent latency trials: the P4 program's bloom-dedup means each
# source IP only ever fires ONE digest per switch lifetime, so a single long
# replay can't produce multiple real latency samples the way the thesis's
# "median over N trials" methodology implies. Instead: reset the switch to a
# clean state, replay a small real attacker-only packet slice (crosses the
# CMS threshold=100 exactly once), record the one real digest-to-mitigation
# latency it produces, repeat N times. Real trial count is reported --
# not padded or assumed to match the thesis's claimed 500.
set -e
cd "$(dirname "$0")/.."

N_TRIALS="${1:-15}"
RESULTS_DIR="/tmp/latency_trials"
rm -rf "$RESULTS_DIR"
mkdir -p "$RESULTS_DIR"

for i in $(seq 1 "$N_TRIALS"); do
  echo "[trial $i/$N_TRIALS] resetting topology..."
  bash scripts/setup_topology.sh > /tmp/topo_reset_trial.log 2>&1
  sudo chmod 666 /tmp/bmv2-0-notifications.ipc

  echo "[trial $i/$N_TRIALS] starting controller (waiting for full startup -- xgboost import alone takes ~18s from /mnt/c)..."
  sudo setsid nohup .venv/bin/python -u -m controller.app \
    --duration 90 --interfaces veth-h1-br,veth-h2-br \
    > /tmp/controller_trial_$i.log 2>&1 < /dev/null &
  disown
  # poll the log for the real "ready" line instead of a blind sleep guess
  for wait_s in $(seq 1 40); do
    if grep -q "digest listener active" /tmp/controller_trial_$i.log 2>/dev/null; then
      echo "[trial $i/$N_TRIALS] controller ready after ${wait_s}s"
      break
    fi
    sleep 1
  done

  # --multiplier=1.0 preserves the pcap's REAL original inter-packet timing
  # (not a fixed --pps rate) -- our features are timing-based (inter_arrival,
  # pkt_rate), so a fixed-rate replay distorts them relative to what the
  # model actually learned. Verified: --pps=200 misclassified the real
  # attacker as benign (1.7% malicious); --multiplier=1.0 correctly got 77.4%.
  echo "[trial $i/$N_TRIALS] replaying real attacker trigger slice at real original timing (~32s)..."
  sudo tcpreplay --intf1=veth-h1-br --multiplier=1.0 --loop=1 \
    "/mnt/d/Smriti PhD/extracted_sample/attacker_trigger_slice.pcap" > /tmp/replay_trial_$i.log 2>&1

  echo "[trial $i/$N_TRIALS] waiting for digest processing..."
  sleep 6

  echo "[trial $i/$N_TRIALS] stopping controller gracefully (SIGTERM, so it exports real results before exiting)..."
  sudo pkill -f "controller.app" 2>/dev/null || true
  sleep 2

  if [ -f evaluation_output/stage_timings.json ]; then
    cp evaluation_output/stage_timings.json "$RESULTS_DIR/trial_$i.json"
    echo "[trial $i/$N_TRIALS] saved: $(cat "$RESULTS_DIR/trial_$i.json" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(f"{len(d)} digest event(s)", d)')"
  else
    echo "[trial $i/$N_TRIALS] WARNING: no stage_timings.json produced"
  fi
done

echo "[trials] merging $N_TRIALS trial results..."
python3 -c "
import json, glob
all_trials = []
for i, f in enumerate(sorted(glob.glob('$RESULTS_DIR/trial_*.json'), key=lambda p: int(p.split('_')[-1].split('.')[0])), start=1):
    data = json.load(open(f))
    for row in data:
        row['trial'] = i
        all_trials.append(row)
with open('evaluation_output/latency_trials.json', 'w') as out:
    json.dump(all_trials, out, indent=2)
print(f'{len(all_trials)} real digest-triggered latency samples across $N_TRIALS trial attempts')
if all_trials:
    totals = sorted(r['total_ms'] for r in all_trials)
    n = len(totals)
    median = totals[n//2] if n % 2 else (totals[n//2-1]+totals[n//2])/2
    print(f'median total_ms: {median:.3f}')
    print(f'min: {totals[0]:.3f}, max: {totals[-1]:.3f}')
"
