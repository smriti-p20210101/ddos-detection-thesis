#include <core.p4>
#include <v1model.p4>

// Define headers
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

struct standard_metadata_t {
    bit<9> ingress_port;
    bit<9> egress_spec;
    bit<9> egress_port;
    bit<32> instance_type;
    bit<32> packet_length;
    bit<32> enq_timestamp;
    bit<19> enq_qdepth;
    bit<32> deq_timedelta;
    bit<32> deq_qdepth;
    bit<48> ingress_global_timestamp;
    bit<48> egress_global_timestamp;
    bit<16> mcast_grp;
    bit<16> egress_rid;
    bit<1> checksum_error;
    bit<32> parser_error;
    bit<3> priority;
}

struct metadata_t {
    bit<10> flow_hash;
    bit<32> counter_val;
    bit<1>  reported_val;
}

// 1. Define the ultra-compact digest payload
struct alert_digest_t {
    bit<32> srcAddr;
    bit<9>  ingress_port;
}

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
    
    // Threshold T
    const bit<32> THRESHOLD = 100;
    
    // Drop Action
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    // Forward Action
    action ipv4_forward(macAddr_t dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    // TCAM Drop Table
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
    
    // Forwarding Table
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
    
    // State Registers for CMS and Bloom Deduplication
    register<bit<32>>(1024) cms_reg;
    register<bit<1>>(1024) bloom_reg;
    
    apply {
        if (hdr.ipv4.isValid()) {
            // Stage 1: Drop Table Exact Match
            if (drop_table.apply().hit) {
                // Do nothing, action already drops
            } else {
                // Stage 2: Hash ALU
                hash(meta.flow_hash, HashAlgorithm_t.crc16, (bit<10>)0, {hdr.ipv4.srcAddr}, (bit<10>)1023);
                
                // Stage 3: CMS Accounting
                cms_reg.read(meta.counter_val, (bit<32>)meta.flow_hash);
                meta.counter_val = meta.counter_val + 1;
                cms_reg.write((bit<32>)meta.flow_hash, meta.counter_val);
                
                // Stage 4: Alerting & Bloom Deduplication
                if (meta.counter_val > THRESHOLD) {
                    bloom_reg.read(meta.reported_val, (bit<32>)meta.flow_hash);
                    if (meta.reported_val == 0) {
                        // Generate Digest
                        alert_digest_t alert;
                        alert.srcAddr = hdr.ipv4.srcAddr;
                        alert.ingress_port = standard_metadata.ingress_port;
                        // emit 28-Byte Alert payload struct
                        // In P4 Runtime we use a digest call:
                        // digest(1, alert); 
                        
                        bloom_reg.write((bit<32>)meta.flow_hash, 1);
                    }
                }
                
                // Normal Forwarding
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
            HashAlgorithm_t.csum16
        );
    }
}

parser MyDeparser(packet_out packet, in parsed_headers_t hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

// Switch instantiation
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
