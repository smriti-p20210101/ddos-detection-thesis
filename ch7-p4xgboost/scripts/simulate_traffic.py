import argparse
import time

def simulate_traffic(vector: str, pps: int, duration: float):
    print(f"[TRex] Initializing simulated DPDK traffic generator...")
    time.sleep(0.5)
    
    if vector == "syn_flood":
        print(f">> Generating {pps/1e6:.1f} Mpps TCP SYN Flood against 192.168.1.100")
        print(f">> Simulated Bandwidth: 3.4 Tbps")
    elif vector == "dns_amplification":
        print(f">> Generating {pps/1e6:.1f} Mpps DNS Amplification (UDP/53) spoofing 10.0.0.5")
        print(f">> Simulated Bandwidth: 1.2 Tbps")
    else:
        print(f">> Replaying benign web traffic logs at {pps} PPS")
        print(f">> Simulated Bandwidth: 15 Mbps")
        
    steps = 5
    sleep_step = duration / steps
    for i in range(steps):
        print(f"   [Tx] Sending traffic burst (Step {i+1}/{steps})")
        time.sleep(sleep_step)
        
    if vector != "benign":
        print("\n[Analysis] P4 Pipeline has mitigated traffic automatically via Count-Min Sketch thresholds.")
        print("[Analysis] Forwarding limited diagnostics to XGBoost control plane.")
    else:
        print("\n[Analysis] Traffic successfully routed via standard L2/L3 tables. No sketches triggered.")

def main():
    parser = argparse.ArgumentParser(description="P4-XGBoost TRex Traffic Simulator")
    parser.add_argument("--vector", type=str, default="syn_flood", choices=["syn_flood", "dns_amplification", "benign"], help="Attack or traffic vector")
    parser.add_argument("--pps", type=int, default=5000000, help="Packets per second")
    parser.add_argument("--duration", type=float, default=0.5, help="Simulation duration (s)")
    args = parser.parse_args()
    
    simulate_traffic(args.vector, args.pps, args.duration)

if __name__ == "__main__":
    main()

