/* poseidon_lite.p4 -- BMv2 v1model (P4_16) functional re-creation of
 * POSEIDON's SYN-flood and DNS-amplification defence policies
 * (Zhang et al., NDSS 2020, Appendix B / Figures 4-5).
 *
 * SCOPE NOTE: POSEIDON released no public code, so this is written directly
 * from the paper's policy-language examples and its Appendix B P4 sketch
 * (which was itself P4-14-style pseudocode). It re-creates:
 *   - count(P, h, every) monitors as count-min-style registers (§V-A)
 *   - the SYN-flood policy: drop if SYN-ACK asymmetry high, pass if
 *     balanced, else route to the sproxy path (Fig. 4)
 *   - the DNS-amplification policy: rate-limit + only allow DNS replies
 *     that match an outstanding query (Fig. 5), using a BMv2 `meter` for
 *     rlimit() and a register-backed set for the "matched query" test in
 *     place of POSEIDON's server-only KVStore.
 * NOT re-created: the ILP-based primitive placement across switch+server
 * (§V), and the `puzzle` (CAPTCHA) action, which POSEIDON itself runs
 * entirely on a server and is orthogonal to data-plane detection.
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4_addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_TCP = 6;
const bit<8>  PROTO_UDP = 17;
const bit<16> DNS_PORT  = 53;

const bit<32> REG_SIZE = 1024;
const bit<32> SYN_ACK_ASYM_T = 15;   // same order of magnitude as jaqen_lite's ASYM_THRESH

header ethernet_t { mac_addr_t dstAddr; mac_addr_t srcAddr; bit<16> etherType; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen;
    bit<16> identification; bit<3> flags; bit<13> fragOffset; bit<8> ttl;
    bit<8> protocol; bit<16> hdrChecksum; ip4_addr_t srcAddr; ip4_addr_t dstAddr;
}
header tcp_t {
    bit<16> srcPort; bit<16> dstPort; bit<32> seqNo; bit<32> ackNo;
    bit<4> dataOffset; bit<3> res; bit<1> cwr; bit<1> ece; bit<1> urg;
    bit<1> ack; bit<1> psh; bit<1> rst; bit<1> syn; bit<1> fin;
    bit<16> window; bit<16> checksum; bit<16> urgentPtr;
}
header udp_t { bit<16> srcPort; bit<16> dstPort; bit<16> length_; bit<16> checksum; }

struct headers { ethernet_t ethernet; ipv4_t ipv4; tcp_t tcp; udp_t udp; }

struct metadata {
    bit<32> idx;
    bit<32> syn_val;
    bit<32> ack_val;
    bit<32> query_idx;
    bit<1>  dns_matched;
}

/* Server-side "sproxy" and "puzzle" cannot execute on the switch (they are
   server-only in the original paper too); a compact alert lets the
   controller decide whether to hand the flow to a software SYN-proxy
   implementation. */
struct poseidon_alert_t {
    bit<32> srcAddr;
    bit<8>  verdict; // 0 = drop, 1 = pass, 2 = sproxy-needed
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                 inout standard_metadata_t std_meta) {
    state start { transition parse_ethernet; }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }
    state parse_tcp { packet.extract(hdr.tcp); transition accept; }
    state parse_udp { packet.extract(hdr.udp); transition accept; }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta,
                   inout standard_metadata_t std_meta) {

    /* count(pkt.tcp.flag == SYN, [ip.src], 5) and
       count(pkt.tcp.flag == ACK, [ip.src], 5)  -- Fig. 4, lines 1-2 */
    register<bit<32>>(REG_SIZE) syn_count_reg;
    register<bit<32>>(REG_SIZE) ack_count_reg;

    /* dns_query = count(pkt.udp.dport == 53, [ip.src], 3600) -- Fig. 5, line 1.
       Register acts as the "has this destination queried DNS recently" set,
       standing in for POSEIDON's server-side KVStore query cache. */
    register<bit<1>>(REG_SIZE) dns_query_seen_reg;

    meter(REG_SIZE, MeterType.packets) dns_rate_meter; /* rlimit() primitive, Fig. 5 */

    action drop_action() { mark_to_drop(std_meta); }
    action pass_action() { /* forward unmodified */ }

    action compute_index(ip4_addr_t addr) {
        hash(meta.idx, HashAlgorithm.crc16, (bit<16>)0, { addr }, (bit<16>)REG_SIZE);
    }

    apply {
        if (!hdr.ipv4.isValid()) { std_meta.egress_spec = 1; return; }

        /* ---------------- SYN-flood policy (paper Fig. 4) ---------------- */
        if (hdr.tcp.isValid()) {
            compute_index(hdr.ipv4.srcAddr);

            if (hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                syn_count_reg.read(meta.syn_val, meta.idx);
                meta.syn_val = meta.syn_val + 1;
                syn_count_reg.write(meta.idx, meta.syn_val);
            }
            if (hdr.tcp.ack == 1) {
                ack_count_reg.read(meta.ack_val, meta.idx);
                meta.ack_val = meta.ack_val + 1;
                ack_count_reg.write(meta.idx, meta.ack_val);
            }

            bit<8> verdict = 2; // default: gray area -> sproxy (line 8-9)
            if (meta.syn_val > meta.ack_val &&
                (meta.syn_val - meta.ack_val) > SYN_ACK_ASYM_T) {
                verdict = 0; // line 4-5: drop
            } else if (meta.syn_val == meta.ack_val) {
                verdict = 1; // line 6-7: pass
            }

            if (verdict == 0) { drop_action(); return; }
            if (verdict == 2) {
                poseidon_alert_t alert;
                alert.srcAddr = hdr.ipv4.srcAddr;
                alert.verdict = verdict;
                digest<poseidon_alert_t>(1, alert); // hand off to server-side sproxy
            }
        }

        /* ------------- DNS-amplification policy (paper Fig. 5) ------------- */
        if (hdr.udp.isValid() && hdr.udp.srcPort == DNS_PORT) {
            compute_index(hdr.ipv4.dstAddr); // query cache keyed by protected server
            dns_query_seen_reg.read(meta.dns_matched, meta.idx);

            if (meta.dns_matched == 1) {
                bit<32> color; // BMv2 meter execute_meter usage
                dns_rate_meter.execute_meter<bit<32>>(meta.idx, color);
                if (color != 0) { drop_action(); return; } // over rate -> drop
                pass_action();
            } else {
                drop_action(); // unmatched DNS reply -> drop (line 5-7)
                return;
            }
        }
        if (hdr.udp.isValid() && hdr.udp.dstPort == DNS_PORT) {
            /* Outbound DNS query from a protected server: mark as seen so the
               matching reply is allowed through. */
            compute_index(hdr.ipv4.srcAddr);
            dns_query_seen_reg.write(meta.idx, 1);
        }

        std_meta.egress_spec = 1;
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyDeparser(packet_out packet, in headers hdr) {
    apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); packet.emit(hdr.tcp); packet.emit(hdr.udp); }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
