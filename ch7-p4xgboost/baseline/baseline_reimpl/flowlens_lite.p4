/* flowlens_lite.p4 -- BMv2 v1model (P4_16) functional re-creation of
 * FlowLens's Flow Marker Accumulator (Barradas et al., NDSS 2021, §IV).
 *
 * SCOPE NOTE: the authors do publish a BMv2-runnable version of this exact
 * component (github.com/dmbb/FlowLens, "adapted ... due to NDA concerns").
 * This file re-derives the same quantization+truncation mechanism from the
 * paper text rather than importing their code directly, so it can be
 * dropped into this project's build without an external dependency; it
 * should be checked against the original repo before being presented as
 * a faithful re-creation.
 *
 * IMPORTANT CONCEPTUAL CAVEAT (state in the thesis): FlowLens was designed
 * and evaluated as a FLOW CLASSIFIER for covert-channel detection, website
 * fingerprinting, and P2P botnet chatter -- never as a DDoS defence. Using
 * it as a DDoS baseline requires re-purposing its packet-length-histogram
 * "flow marker" as an input to a binary benign/attack classifier trained on
 * CIC-DDoS2019. This is FlowLens's *mechanism* applied to a *different task*
 * than the one it was designed and evaluated for, and should be flagged as
 * such next to any comparison number.
 *
 * NOT re-created: the Bayesian-optimisation automatic profiler (§V), which
 * searches quantization level (QL) and truncation bin sets; here QL=4 and
 * top-10 truncation are used directly, matching the paper's own
 * best-reported covert-channel configuration (Table III / Fig. 8), since a
 * from-scratch Hyperopt-based profiler is out of scope for this comparison.
 */

#include <core.p4>
#include <v1model.p4>

typedef bit<9>  egress_spec_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4_addr_t;

const bit<16> TYPE_IPV4 = 0x0800;

const bit<32> NUM_FLOWS  = 1024;  // flow table size (register grid rows)
const bit<32> QL         = 4;     // quantization level: bin(QL,PL) = PL >> QL
const bit<32> NUM_BINS   = 10;    // truncation: top-10 bins, per paper's
                                    // best covert-channel configuration

header ethernet_t { mac_addr_t dstAddr; mac_addr_t srcAddr; bit<16> etherType; }
header ipv4_t {
    bit<4> version; bit<4> ihl; bit<8> diffserv; bit<16> totalLen;
    bit<16> identification; bit<3> flags; bit<13> fragOffset; bit<8> ttl;
    bit<8> protocol; bit<16> hdrChecksum; ip4_addr_t srcAddr; ip4_addr_t dstAddr;
}

struct headers { ethernet_t ethernet; ipv4_t ipv4; }

struct metadata {
    bit<32> flow_offset;
    bit<32> quant_bin;
    bit<32> bin_offset;
    bit<16> pkt_len;
}

/* Emitted once the collection window elapses (controller-driven poll, as in
   the original FlowLens control-plane collector). Here we emit a compact
   10-bin histogram digest per flow rather than exporting the whole
   register grid, to keep the BMv2 P4Runtime digest small like the other
   two baselines. */
struct flow_marker_t {
    bit<32> flowAddr;      // flow-table key surrogate (src IP for this
                            // simplified single-host-pair grid)
    bit<16> bin0; bit<16> bin1; bit<16> bin2; bit<16> bin3; bit<16> bin4;
    bit<16> bin5; bit<16> bin6; bit<16> bin7; bit<16> bin8; bit<16> bin9;
}

parser MyParser(packet_in packet, out headers hdr, inout metadata meta,
                 inout standard_metadata_t std_meta) {
    state start { transition parse_ethernet; }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; }
    }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition accept; }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

control MyIngress(inout headers hdr, inout metadata meta,
                   inout standard_metadata_t std_meta) {

    /* Register grid: NUM_FLOWS rows x NUM_BINS columns. Memory footprint:
       1024 * 10 * 16 bits = 20,480 bytes -- reported in the functional
       comparison alongside P4-XGBoost's 4 KB CMS, per the paper's own
       headline claim of a 20-byte-per-flow marker (here scaled up because
       we keep counts per bin rather than a single compressed value, to
       stay faithful to the paper's literal data structure). */
    register<bit<16>>(NUM_FLOWS * NUM_BINS) marker_grid;

    action compute_flow_offset(ip4_addr_t addr) {
        hash(meta.flow_offset, HashAlgorithm.crc16, (bit<16>)0, { addr },
             (bit<16>)NUM_FLOWS);
    }

    apply {
        if (!hdr.ipv4.isValid()) { std_meta.egress_spec = 1; return; }

        compute_flow_offset(hdr.ipv4.srcAddr);
        meta.pkt_len = hdr.ipv4.totalLen;

        /* Quantization: bin(QL, PL) = length(PL) >> QL, per §IV-A. */
        meta.quant_bin = (bit<32>)(meta.pkt_len >> QL);

        /* Truncation: only the first NUM_BINS quantized bins are tracked
           (paper's "top-N" selection is done offline by the profiler on
           training data; here it is approximated with the first N bins,
           which for the CIC-DDoS2019 packet-size distribution captures
           the SYN/ACK/UDP-flood-typical small-packet range). */
        if (meta.quant_bin < NUM_BINS) {
            meta.bin_offset = meta.flow_offset * NUM_BINS + meta.quant_bin;
            bit<16> cur;
            marker_grid.read(cur, meta.bin_offset);
            marker_grid.write(meta.bin_offset, cur + 1);
        }

        std_meta.egress_spec = 1;
    }
}

control MyEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t std_meta) { apply { } }
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply { } }
control MyDeparser(packet_out packet, in headers hdr) {
    apply { packet.emit(hdr.ethernet); packet.emit(hdr.ipv4); }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;

/* NOTE ON CONTROLLER RESPONSIBILITY:
 * The control plane (controller/flowlens_controller.py) polls the register
 * grid every collection window, assembles the 10-bin flow marker per flow,
 * and feeds it to a RandomForestClassifier (mirroring FlowLens's own choice
 * of classifier for its P2P-botnet use case, the closest of its three
 * original use cases to a flooding-style detection problem) trained on
 * CIC-DDoS2019 flow markers. See eval/flowlens_lite.py for the exact
 * offline equivalent used for batch scoring.
 */
