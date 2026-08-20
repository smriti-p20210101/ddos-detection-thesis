# Jaqen -> jaqen_lite mapping notes

**Source:** Liu, Namkung, Nikolaidis, Lee, Kim, Jin, Braverman, Yu, Sekar.
"Jaqen: A High-Performance Switch-Native Approach for Detecting and
Mitigating Volumetric DDoS Attacks with Programmable Switches." USENIX
Security 2021.

**Public code:** github.com/Froot-NetSys/Jaqen -- SYN-proxy P4-14 module
only (README: "Reposting all P4 modules (ongoing): SYN Proxy, Dec. 2022").
No sketch/detector or resource-manager code is public.

| Paper concept | This re-creation | Deliberately simplified/omitted |
|---|---|---|
| Universal sketch (estimates any L2-bounded statistic: heavy hitters, distinct flows, entropy, traffic change) | Two single-row count registers (SYN, ACK) + one UDP-count register, `d=1` | Only supports counting, not the general L2-norm-bounded estimator class; no entropy or distinct-flow estimation |
| `Query(proto, func, mode, freq)` detection API | Threshold test inlined in the P4 `apply` block, with a digest fired once per source per window | No self-triggering/pulling-mode distinction; single hardcoded query per packet |
| `UDPFlood()` / `DNSFlood()` control-layer logic (Fig. 4) | `syn_val - ack_val > ASYM_THRESH` and `udp_val > UDP_THRESH` tests, directly modelled on the paper's pseudocode | DNSFlood's specific "unmatched DNS replies" logic is folded into POSEIDON-lite instead, since Jaqen's own Fig.4 example for DNS is structurally identical to POSEIDON's |
| Mitigation API (`RateLimit`, `ExactBlockList`, `ApproxBlockList`, `ActionAndTest`, `HeaderHashAndTest`, `UnmatchAndAction`, `KVStore`) | Only `ExactBlockList`-equivalent (`drop_table`) is implemented | The other 10 mitigation building blocks and the SYN-proxy case study are out of scope for this functional-metric comparison |
| Network-wide MIP resource manager (§6) | Not implemented | Requires multi-switch ISP topology + solver; irrelevant to a single-switch accuracy/FPR comparison |

**Threshold choice.** `SYN_THRESH=20`, `UDP_THRESH=50`, `ASYM_THRESH=15` are
starting points tuned against the synthetic smoke-test distribution; **re-tune
against your real CIC-DDoS2019 split** (e.g. via a small grid search reusing
`eval/evaluate_baselines.py`) before reporting final numbers, and record the
chosen values here.

**Known collision-behaviour caveat.** `common.crc16_index()` uses
`zlib.crc32 % REG_SIZE`, not a hardware CRC16 ALU. This is a reasonable
proxy for uniform-hash collision behaviour but is not bit-identical to what
a compiled `p4/jaqen_lite.p4` running on real BMv2 will produce; if you also
run the compiled P4 program, expect small (single-digit) FPR differences
from hash-collision variance and note this in the thesis text.
