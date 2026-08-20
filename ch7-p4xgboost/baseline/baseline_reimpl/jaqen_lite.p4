/* jaqen_lite.p4 -- BMv2 v1model (P4_16) functional re-creation of Jaqen's
 * always-on detection layer (Liu et al., USENIX Security 2021).
 *
 * SCOPE NOTE: this file re-creates only the two example detectors given in
 * Jaqen's Figure 4 (UDPFlood via heavy-hitter count, SYN-flood via
 * SYN/ACK asymmetry) using a simplified single-row Count-Min-style register
 * array. It does NOT re-implement:
 *   - the full "universal sketch" (which estimates arbitrary L2-bounded
 *     statistics, not just counts),
 *   - the mitigation-function library (ExactBlockList, ApproxAllowList,
 *     HeaderHashAndTest, UnmatchAndAction, etc.),
 *   - the network-wide MIP resource manager.
 * Tofino-only primitives with no BMv2 equivalent (stateful ALUs via
 * register_lo/register_hi blackboxes, hardware hash ALUs, TCAM-backed
 * approximate structures) are replaced here with BMv2 v1model `register`
 * externs and the built-in `hash()` primitive (CRC16-based), per the
 * mapping documented in docs/jaqen_lite.md.
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4_addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8>  PROTO_TCP = 6;
const bit<8>  PROTO_UDP = 17;

const bit<32> REG_SIZE     = 1024;   // matches P4-XGBoost's 1024-entry CMS
                                       // for a like-for-like memory comparison
const bit<32> SYN_THRESH   = 20;      // packets / window, tuned to CIC-DDoS2019
const bit<32> UDP_THRESH   = 50;      // packets / window (heavy-hitter test)
const bit<32> ASYM_THRESH  = 15;      // SYN - ACK asymmetry threshold

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>    etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4_addr_t srcAddr;
    ip4_addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct metadata {
    bit<32> idx;
    bit<32> syn_val;
    bit<32> ack_val;
    bit<32> udp_val;
    bit<1>  is_attack;
}

/* --- Digest sent to controller: mirrors Jaqen's "victim/srcprefix/type/vol"
   detection-event output, compacted to fit BMv2's digest mechanism. --- */
struct jaqen_alert_t {
    bit<32> srcAddr;
    bit<8>  attack_type;   // 1 = SYN asymmetry, 2 = UDP heavy hitter
    bit<32> metric_value;
}

parser MyParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t std_meta) {
    state start { transition parse_ethernet; }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
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

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t std_meta) {

    /* Two independent single-row registers stand in for Jaqen's universal
       sketch instances (SrcIP sketch for SYN count, SrcIP sketch for ACK
       count) plus a third for UDP packet counts. Memory: 3 x 1024 x 32 bits
       = 12,288 bytes -- reported alongside accuracy in Table 7.6. */
    register<bit<32>>(REG_SIZE) syn_count_reg;
    register<bit<32>>(REG_SIZE) ack_count_reg;
    register<bit<32>>(REG_SIZE) udp_count_reg;
    register<bit<1>>(REG_SIZE)  reported_reg; /* dedup, same pattern as P4-XGBoost */

    action drop_action() { mark_to_drop(std_meta); }
    action allow_action() { /* no-op: forward as normal */ }

    table drop_table {
        key = { hdr.ipv4.srcAddr: exact; }
        actions = { drop_action; NoAction; }
        size = 4096;
        default_action = NoAction();
    }

    action compute_index(ip4_addr_t addr) {
        hash(meta.idx, HashAlgorithm.crc16, (bit<16>)0, { addr }, (bit<16>)REG_SIZE);
    }

    apply {
        if (drop_table.apply().hit) {
            return; /* already confirmed malicious by controller */
        }

        if (hdr.ipv4.isValid()) {
            compute_index(hdr.ipv4.srcAddr);

            if (hdr.tcp.isValid() && hdr.tcp.syn == 1 && hdr.tcp.ack == 0) {
                syn_count_reg.read(meta.syn_val, meta.idx);
                meta.syn_val = meta.syn_val + 1;
                syn_count_reg.write(meta.idx, meta.syn_val);
            }
            if (hdr.tcp.isValid() && hdr.tcp.ack == 1 && hdr.tcp.syn == 0) {
                ack_count_reg.read(meta.ack_val, meta.idx);
                meta.ack_val = meta.ack_val + 1;
                ack_count_reg.write(meta.idx, meta.ack_val);
            }
            if (hdr.udp.isValid()) {
                udp_count_reg.read(meta.udp_val, meta.idx);
                meta.udp_val = meta.udp_val + 1;
                udp_count_reg.write(meta.idx, meta.udp_val);
            }

            /* Jaqen Fig. 4 UDPFlood()/DNSFlood() logic: threshold test with
               a dedup bit so exactly one alert per source per window is
               emitted -- reusing the same deduplication idea validated in
               Ch7's ablation 4, applied here to Jaqen's detector for a
               like-for-like memory/behaviour comparison. */
            bit<1> already_reported;
            reported_reg.read(already_reported, meta.idx);

            meta.is_attack = 0;
            bit<8> a_type = 0;
            bit<32> a_val = 0;

            if (meta.syn_val > SYN_THRESH && meta.syn_val - meta.ack_val > ASYM_THRESH) {
                meta.is_attack = 1; a_type = 1; a_val = meta.syn_val;
            } else if (meta.udp_val > UDP_THRESH) {
                meta.is_attack = 1; a_type = 2; a_val = meta.udp_val;
            }

            if (meta.is_attack == 1 && already_reported == 0) {
                jaqen_alert_t alert;
                alert.srcAddr = hdr.ipv4.srcAddr;
                alert.attack_type = a_type;
                alert.metric_value = a_val;
                digest<jaqen_alert_t>(1, alert);
                reported_reg.write(meta.idx, 1);
            }
        }
        std_meta.egress_spec = 1; /* single-port testbed default; replace with real fwd table */
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
