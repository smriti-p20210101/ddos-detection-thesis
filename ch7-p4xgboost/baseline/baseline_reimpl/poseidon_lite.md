# POSEIDON -> poseidon_lite mapping notes

**Source:** Zhang, Li, Wang, Liu, Chen, Hu, Gu, Li, Xu, Wu. "Poseidon:
Mitigating Volumetric DDoS Attacks with Programmable Switches." NDSS 2020.

**Public code:** none. NSF public-access record (par.nsf.gov/biblio/10176415)
lists "Country unknown / Code not available." This re-creation is written
directly from the paper's policy-language examples (§IV-B, Figs. 4-5) and
its Appendix B P4 sketch, then modernised from the paper's P4-14-style
pseudocode to P4_16/v1model syntax so it compiles for BMv2.

| Paper concept | This re-creation | Deliberately simplified/omitted |
|---|---|---|
| `count(P, h, every)` / `aggr(P, h, every)` monitors, built on count-min sketch (§V-A) | Single-row count registers per metric (SYN, ACK) | Full count-min sketch with `d` rows and error-bound guarantees `ε, δ` not implemented; single-row approximation only |
| SYN-flood policy (Fig. 4): drop if `syn_count - ack_count > T`, pass if equal, else `sproxy` | `poseidon_lite.p4` ingress branching, verbatim structure | -- |
| `sproxy` (SYN Proxy / cookie verification) | Digest to controller; `SoftwareSynProxy` class in `controller/poseidon_controller.py` verifies via a stored cookie dict, not a real cookie round-trip over the wire | POSEIDON's own sproxy is itself server-only in the original paper -- this matches that split, just without DPDK-level packet I/O |
| DNS-amplification policy (Fig. 5): rate-limit + drop unmatched replies | `dns_query_seen_reg` (query cache) + BMv2 `meter` for rate limiting | POSEIDON's own KVStore-based query cache assumed unbounded; here it shares `REG_SIZE` with the other registers, so it can evict/collide under load the paper's version might not |
| `puzzle` (CAPTCHA for HTTP flood) | Not implemented | Explicitly server-only and orthogonal to volumetric/data-plane detection; irrelevant to the four CIC-DDoS2019 attack types used in Ch7 (SYN, UDP amp, HTTP POST flood, Slowloris) except loosely for HTTP POST flood, which this re-creation does not specifically target |
| ILP-based primitive placement across switch/server (§V) | Not implemented | Assumes a hardware-constrained multi-stage pipeline (limited SRAM/ALUs per stage) that BMv2 does not enforce; the placement problem is meaningless without that constraint |

**Offline gray-area resolution caveat.** `eval/poseidon_lite.py`'s
`gray_attack` heuristic (flows with SYN/ACK counts that don't fit cleanly
into "drop" or "pass" are flagged attack unless they show signs of a
completed handshake) is an *approximation* of the real cookie-verification
outcome, since CIC-DDoS2019 flow records don't carry a raw TCP cookie
exchange to replay. If your CSV includes packet-level TCP sequence numbers,
consider replacing this heuristic with an actual cookie-style check for a
tighter match to the paper's mechanism.
