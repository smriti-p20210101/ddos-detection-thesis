// Real ablation 6 (digest payload size) substitute experiment.
//
// The original thesis ablation compared a "28-byte" digest against a
// "1500-byte" digest's effect on "gRPC transmission latency" -- neither
// number has any real basis (the real control plane is Thrift/nanomsg, not
// gRPC; the real digest struct is 6 bytes, not 28; see
// CHAPTER7_REBUILD_REPORT.md for the full explanation). Comparing real
// BMv2 throughput against a Tofino ASIC's >5,000 alerts/sec claim is
// explicitly infeasible (a software reference switch can't reproduce ASIC
// line-rate behavior) -- that part of the original ablation stays dropped.
//
// This is a real, narrower, feasible substitute: does real digest
// payload size measurably affect real Thrift/nanomsg notification
// receive+decode latency on THIS switch? A direct copy of
// p4/p4_xgboost.p4's real detection logic (same parser, same CMS/bloom
// trigger conditions), with only the alert_digest_t struct size varied via
// a compile-time -DPADDING_BITS flag -- compile with no flag for the real
// baseline (6 bytes, matches production exactly), or e.g.
// -DPADDING_BITS=752 (+94 bytes -> ~100 bytes total) or
// -DPADDING_BITS=11712 (+1464 bytes -> ~1500 bytes total, chosen only to
// give a real result at the same size the (unfounded) original thesis
// number referenced, for a recognizable comparison point -- not because
// that original number is trusted).
#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
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

struct parsed_headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}

struct metadata_t {
    bit<10> flow_hash;
    bit<32> counter_val;
    bit<1>  reported_val;
}

// Real production struct (p4/p4_xgboost.p4): bit<32> srcAddr + bit<9>
// ingress_port = 41 bits, padded by BMv2 to 6 bytes (verified against a
// live digest -- see controller/p4/digest_listener.py's SAMPLE_LEN=6
// comment). PADDING_BITS is 0 (i.e. absent) unless passed via -D.
//
// p4c caps a single field at 2048 bits (256 bytes), so the ~1500-byte
// (11712-bit) test point (LARGE_PADDING) is real but built from 6 fields
// of 1952 bits each (244 bytes x 6 = 1464 bytes), not one field -- a real
// compiler constraint, not an arbitrary choice.
#if defined(LARGE_PADDING)
struct alert_digest_t {
    bit<32> srcAddr;
    bit<9>  ingress_port;
    bit<1952> padding1;
    bit<1952> padding2;
    bit<1952> padding3;
    bit<1952> padding4;
    bit<1952> padding5;
    bit<1952> padding6;
}
#elif defined(PADDING_BITS)
struct alert_digest_t {
    bit<32> srcAddr;
    bit<9>  ingress_port;
    bit<PADDING_BITS> padding;
}
#else
struct alert_digest_t {
    bit<32> srcAddr;
    bit<9>  ingress_port;
}
#endif

parser MyParser(packet_in packet,
                out parsed_headers_t hdr,
                inout metadata_t meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(inout parsed_headers_t hdr, inout metadata_t meta) {
    apply { }
}

control MyIngress(inout parsed_headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    const bit<32> THRESHOLD = 100;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table drop_table {
        key = {
            hdr.ipv4.srcAddr : exact;
        }
        actions = {
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    register<bit<32>>(1024) cms_reg;
    register<bit<1>>(1024) bloom_reg;

    apply {
        if (hdr.ipv4.isValid()) {
            if (drop_table.apply().hit) {
                // Do nothing, action already drops
            } else {
                hash(meta.flow_hash, HashAlgorithm.crc16, (bit<10>)0, {hdr.ipv4.srcAddr}, (bit<10>)1023);

                cms_reg.read(meta.counter_val, (bit<32>)meta.flow_hash);
                meta.counter_val = meta.counter_val + 1;
                cms_reg.write((bit<32>)meta.flow_hash, meta.counter_val);

                if (meta.counter_val > THRESHOLD) {
                    bloom_reg.read(meta.reported_val, (bit<32>)meta.flow_hash);
                    if (meta.reported_val == 0) {
                        alert_digest_t alert;
                        alert.srcAddr = hdr.ipv4.srcAddr;
                        alert.ingress_port = standard_metadata.ingress_port;
#if defined(LARGE_PADDING)
                        alert.padding1 = 0;
                        alert.padding2 = 0;
                        alert.padding3 = 0;
                        alert.padding4 = 0;
                        alert.padding5 = 0;
                        alert.padding6 = 0;
#elif defined(PADDING_BITS)
                        alert.padding = 0;
#endif
                        digest<alert_digest_t>(1, alert);

                        bloom_reg.write((bit<32>)meta.flow_hash, 1);
                    }
                }

                ipv4_lpm.apply();
            }
        }
    }
}

control MyEgress(inout parsed_headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout parsed_headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
