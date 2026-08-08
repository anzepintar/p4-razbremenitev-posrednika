#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;

const bit<9> PORT_CLIENT = 1;
const bit<9> PORT_SERVER = 2;
const bit<9> PORT_MITM   = 3;
const bit<32> STAT_NOT_IPV4 = 0;
const bit<32> STAT_NO_ROUTE = 1;
const bit<32> STAT_TTL      = 2;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

struct metadata {
    bit<1> steered;
}

parser SwitchParser(packet_in packet,
                    out headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
    state start {
        meta.steered = 0;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control SwitchVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control SwitchIngress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    counter(3, CounterType.packets) stats;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dmac, macAddr_t smac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ethernet.srcAddr = smac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action no_route() {
        stats.count(STAT_NO_ROUTE);
        mark_to_drop(standard_metadata);
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; no_route; }
        default_action = no_route();
        const entries = {
            32w0x0a000100 &&& 32w0xffffff00 :
                ipv4_forward(48w0x00000000010a, 48w0x0000000001fe, PORT_CLIENT);
            32w0x0a000200 &&& 32w0xffffff00 :
                ipv4_forward(48w0x00000000020a, 48w0x0000000002fe, PORT_SERVER);
            32w0x0a000300 &&& 32w0xffffff00 :
                ipv4_forward(48w0x00000000030a, 48w0x0000000003fe, PORT_MITM);
        }
    }

    direct_counter(CounterType.packets_and_bytes) steering_ctr;

    action direct() {
        steering_ctr.count();
    }

    action via_mitm(macAddr_t dmac, macAddr_t smac) {
        standard_metadata.egress_spec = PORT_MITM;
        hdr.ethernet.dstAddr = dmac;
        hdr.ethernet.srcAddr = smac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.steered = 1;
        steering_ctr.count();
    }

    action mirror(bit<32> session) {
        clone(CloneType.I2E, session);
        steering_ctr.count();
    }

    table steering {
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.srcAddr:               exact;
        }
        actions = { direct; via_mitm; mirror; }
        size = 64;
        default_action = direct();
        counters = steering_ctr;
    }

    apply {
        if (!hdr.ipv4.isValid()) {
            stats.count(STAT_NOT_IPV4);
            drop();
            return;
        }
        if (hdr.ipv4.ttl <= 1) {
            stats.count(STAT_TTL);
            drop();
            return;
        }

        steering.apply();
        if (meta.steered == 0) {
            ipv4_lpm.apply();
        }
    }
}

control SwitchEgress(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {
    apply { }
}

control SwitchComputeChecksum(inout headers hdr, inout metadata meta) {
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
            HashAlgorithm.csum16);
    }
}

control SwitchDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    SwitchParser(),
    SwitchVerifyChecksum(),
    SwitchIngress(),
    SwitchEgress(),
    SwitchComputeChecksum(),
    SwitchDeparser()
) main;
