/* ============================================================
 * gossip_detect.p4
 *
 * Scalable, Low-Latency, Decentralised DDoS Detection Using
 * Gossip Protocols in Programmable Data Plane
 *
 * Implements Algorithms 1-4 from:
 *   Smriti Smriti, HariBabu K, Mohaneesh Raj Pradhan,
 *   Nitin Varyani. ACM Journal, 2026.
 *
 * Architecture : BMv2 v1model (p4app / Mininet)
 * Detection    : Count-Min Sketch, threshold τ = 5
 * Dissemination: Anti-Entropy (SYNC) and
 *                Rumor-Mongering (ALERT) gossip protocols
 * ============================================================ */

#include <core.p4>
#include <v1model.p4>

/* ============================================================
 * CONSTANTS  (match paper Section 5, Table 6)
 * ============================================================ */
const bit<16> TYPE_IPV4    = 0x0800;
const bit<16> TYPE_GOSSIP  = 0x9999;   /* custom ethertype    */
const bit<8>  FLAG_ALERT   = 1;        /* Rumor-Mongering     */
const bit<8>  FLAG_SYNC    = 2;        /* Anti-Entropy        */
const bit<32> SKETCH_SIZE  = 1024;     /* Config A — 4 KB     */
const bit<32> THRESHOLD    = 5;        /* τ ≥ 5 (Section 5.4) */

/* ============================================================
 * HEADERS  —  Algorithm 4
 * ============================================================ */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

/* Custom gossip header — Algorithm 4, lines 2-5 */
header gossip_t {
    bit<32> gossip_id;    /* unique alert event identifier */
    bit<8>  gossip_flag;  /* ALERT = 1, SYNC = 2           */
}

/* Algorithm 4, lines 7-12 */
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    gossip_t   gossip;
}

struct metadata {
    bit<32> sketch_idx;
    bit<32> pkt_count;
    bit<1>  is_attack;
    bit<32> gossip_id;
}

/* ============================================================
 * PARSER
 * ============================================================ */
parser MyParser(
    packet_in           packet,
    out headers         hdr,
    inout metadata      meta,
    inout standard_metadata_t smeta)
{
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4   : parse_ipv4;
            TYPE_GOSSIP : parse_gossip;
            default     : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    /* Gossip packets carry the custom header instead of IPv4 */
    state parse_gossip {
        packet.extract(hdr.gossip);
        transition accept;
    }
}

/* ============================================================
 * VERIFY CHECKSUM
 * ============================================================ */
control MyVerifyChecksum(
    inout headers   hdr,
    inout metadata  meta) {
    apply { }
}

/* ============================================================
 * INGRESS CONTROL  —  Algorithm 1 (detection) +
 *                     Algorithms 2/3 (gossip trigger)
 * ============================================================ */
control MyIngress(
    inout headers               hdr,
    inout metadata              meta,
    inout standard_metadata_t   smeta)
{
    /* --- Count-Min Sketch register array (Config A = 1024) --- */
    register<bit<32>>(SKETCH_SIZE) sketch_reg;

    /* --- Forwarding table ------------------------------------ */
    action forward(bit<9> egress_port) {
        smeta.egress_spec = egress_port;
    }

    action drop_pkt() {
        mark_to_drop(smeta);
    }

    table ipv4_fwd {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions   = { forward; drop_pkt; }
        default_action = drop_pkt();
    }

    /* --- Gossip forwarding table ----------------------------- */
    table gossip_fwd {
        key = {
            smeta.ingress_port : exact;
        }
        actions   = { forward; drop_pkt; }
        default_action = drop_pkt();
    }

    /* --- Attack detection and gossip trigger ----------------- */
    action handle_ddos() {
        /* Algorithm 1, lines 3-4: hash SrcIP to sketch index   */
        hash(meta.sketch_idx,
             HashAlgorithm.crc32,
             (bit<32>)0,
             { hdr.ipv4.srcAddr },
             SKETCH_SIZE);

        /* Algorithm 1, lines 5-6: read-modify-write            */
        sketch_reg.read(meta.pkt_count,
                        (bit<32>)meta.sketch_idx);
        meta.pkt_count = meta.pkt_count + 1;
        sketch_reg.write((bit<32>)meta.sketch_idx,
                         meta.pkt_count);

        /* Algorithm 1, lines 7-10: threshold decision          */
        if (meta.pkt_count + 1 > THRESHOLD) {
            meta.is_attack = 1;
            mark_to_drop(smeta);
            /* gossip_id encodes the attacking source IP         */
            meta.gossip_id = hdr.ipv4.srcAddr;
            /* clone3 triggers gossip dissemination in egress   */
            clone3(CloneType.I2E, 100,
                   { meta.sketch_idx,
                     meta.pkt_count,
                     meta.is_attack,
                     meta.gossip_id });
        } else {
            meta.is_attack = 0;
        }
    }

    apply {
        if (hdr.gossip.isValid()) {
            /* Received a gossip update — forward via gossip_fwd */
            gossip_fwd.apply();
        } else if (hdr.ipv4.isValid()) {
            handle_ddos();
            if (meta.is_attack == 0) {
                ipv4_fwd.apply();
            }
        }
    }
}

/* ============================================================
 * EGRESS CONTROL  —  Gossip packet construction
 *   Anti-Entropy  : FLAG_SYNC  (Algorithm 2)
 *   Rumor-Mongering: FLAG_ALERT (Algorithm 3)
 * ============================================================ */
control MyEgress(
    inout headers               hdr,
    inout metadata              meta,
    inout standard_metadata_t   smeta)
{
    action build_alert_gossip() {
        /* Rumor-Mongering: FLAG_ALERT gossip packet             */
        hdr.ethernet.etherType = TYPE_GOSSIP;
        hdr.gossip.setValid();
        hdr.gossip.gossip_id   = meta.gossip_id;
        hdr.gossip.gossip_flag = FLAG_ALERT;
        hdr.ipv4.setInvalid();
    }

    action build_sync_gossip() {
        /* Anti-Entropy: FLAG_SYNC gossip packet                 */
        hdr.ethernet.etherType = TYPE_GOSSIP;
        hdr.gossip.setValid();
        hdr.gossip.gossip_id   = meta.gossip_id;
        hdr.gossip.gossip_flag = FLAG_SYNC;
        hdr.ipv4.setInvalid();
    }

    apply {
        /* Cloned packets become outbound gossip messages        */
        if (smeta.instance_type == 1) {    /* clone I2E         */
            build_alert_gossip();          /* Rumor-Mongering   */
        }
        /* Periodic Anti-Entropy sync packets are generated      */
        /* by the controller and injected with FLAG_SYNC         */
    }
}

/* ============================================================
 * CHECKSUM UPDATE
 * ============================================================ */
control MyComputeChecksum(
    inout headers   hdr,
    inout metadata  meta)
{
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl,
              hdr.ipv4.diffserv, hdr.ipv4.totalLen,
              hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl,
              hdr.ipv4.protocol, hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/* ============================================================
 * DEPARSER
 * ============================================================ */
control MyDeparser(
    packet_out  packet,
    in headers  hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.gossip);
    }
}

/* ============================================================
 * SWITCH INSTANTIATION
 * ============================================================ */
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
