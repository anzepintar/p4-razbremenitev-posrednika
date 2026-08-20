#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;

const bit<9> PORT_CLIENT = 1;
const bit<9> PORT_SERVER = 2;
const bit<9> PORT_MITM   = 3;

const bit<48> MAC_MITM    = 48w0x00000000030a;
const bit<48> MAC_MITM_GW = 48w0x0000000003fe;

const bit<8>  PROTO_TCP        = 6;
const bit<8>  PROTO_UDP        = 17;
const bit<8>  PROTO_ICMP       = 1;
const bit<16> PORT_TLS         = 443;
const bit<16> PORT_DNS         = 53;
const bit<8>  TLS_HANDSHAKE    = 0x16;
const bit<8>  TLS_CLIENT_HELLO = 0x01;
const bit<16> EXT_SERVER_NAME  = 0;
const bit<8>  SNI_HOST_NAME    = 0;

const bit<8>  MAX_SESSION_ID  = 32;
const bit<16> MAX_CIPHERS     = 256;
const bit<8>  MAX_COMPRESSION = 32;
const bit<16> MAX_EXT_BODY    = 256;
const bit<16> MAX_SNI_NAME    = 63;

const bit<2>  VERDICT_BLOCK = 1;
const bit<2>  VERDICT_WHITE = 2;

const bit<8>  PATH_NONE   = 0;
const bit<8>  PATH_PROXY  = 1;
const bit<8>  PATH_DIRECT = 2;
const bit<8>  PATH_BLOCK  = 3;

const bit<32> QUIC_TIMEOUT_MS = 60000;
const bit<32> QUIC_MAX_FLOWS  = 65536;
const bit<32> QUIC_MAX_CRYPTO = 16384;

const bit<32> STAT_SNI_SEEN     = 0;
const bit<32> STAT_SNI_BLOCKED  = 1;
const bit<32> STAT_SNI_WHITE    = 2;
const bit<32> STAT_QUIC         = 3;
const bit<32> STAT_IP_BLOCKED   = 4;
const bit<32> STAT_IP_WHITE     = 5;
const bit<32> STAT_DENIED       = 6;
const bit<32> STAT_QUIC_SNI     = 7;
const bit<32> STAT_QUIC_BLOCKED = 8;
const bit<32> STAT_QUIC_WHITE   = 9;

extern QuicSni {
    QuicSni(bit<32> flow_timeout_ms, bit<32> max_flows, bit<32> max_crypto,
            bit<32> max_name);
    void classify(in bit<32> srcAddr, in bit<32> dstAddr,
                  in bit<16> srcPort, in bit<16> dstPort, in bit<16> length,
                  out bit<512> sni, out bit<1> found, out bit<8> path);
    void pin(in bit<32> srcAddr, in bit<32> dstAddr,
             in bit<16> srcPort, in bit<16> dstPort, in bit<8> path);
}

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header tls_record_t {
    bit<8>  contentType;
    bit<16> version;
    bit<16> length;
}

header tls_hello_t {
    bit<8>   handshakeType;
    bit<24>  length;
    bit<16>  version;
    bit<256> random;
}

header tls_extension_t {
    bit<16> etype;
    bit<16> elen;
}

header tls_sni_t {
    bit<16> listLen;
    bit<8>  nameType;
    bit<16> nameLen;
}

header len8_t {
    bit<8> value;
}

header len16_t {
    bit<16> value;
}

header part1_t {
    bit<8> value;
}

header part2_t {
    bit<16> value;
}

header part4_t {
    bit<32> value;
}

header part8_t {
    bit<64> value;
}

header part16_t {
    bit<128> value;
}

header part32_t {
    bit<256> value;
}

header varbits256_t {
    varbit<256> value;
}

header varbits320_t {
    varbit<320> value;
}

header varbits2048_t {
    varbit<2048> value;
}

struct headers {
    ethernet_t      ethernet;
    ipv4_t          ipv4;
    udp_t           udp;
    tcp_t           tcp;
    varbits320_t    tcpOptions;
    tls_record_t    tls;
    tls_hello_t     hello;
    len8_t          sessionLen;
    varbits256_t    sessionId;
    len16_t         cipherLen;
    varbits2048_t   ciphers;
    len8_t          compressionLen;
    varbits256_t    compressions;
    len16_t         extensionsLen;
    tls_extension_t extension0;
    varbits2048_t   extensionBody0;
    tls_extension_t extension1;
    varbits2048_t   extensionBody1;
    tls_extension_t extension2;
    varbits2048_t   extensionBody2;
    tls_extension_t extension3;
    varbits2048_t   extensionBody3;
    tls_extension_t extension4;
    varbits2048_t   extensionBody4;
    tls_extension_t extension5;
    varbits2048_t   extensionBody5;
    tls_sni_t       sniHeader;
    part32_t        namePart32;
    part16_t        namePart16;
    part8_t         namePart8;
    part4_t         namePart4;
    part2_t         namePart2;
    part1_t         namePart1;
}

struct metadata {
    bit<1>   steered;
    bit<2>   ipVerdict;
    bit<2>   sniVerdict;
    bit<512> sni;
    bit<1>   sniValid;
    bit<1>   quicFound;
    bit<8>   quicPath;
}

#define TLS_EXTENSION_SLOT(index, nextState)                                      \
    state parse_extension_##index {                                               \
        packet.extract(hdr.extension##index);                                     \
        transition select(hdr.extension##index.etype,                             \
                          hdr.extension##index.elen) {                            \
            (EXT_SERVER_NAME, _):      parse_sni;                                 \
            (_, 16w0 .. MAX_EXT_BODY): skip_extension_##index;                    \
            default:                   accept;                                    \
        }                                                                         \
    }                                                                             \
    state skip_extension_##index {                                                \
        packet.extract(hdr.extensionBody##index,                                  \
                       (bit<32>)hdr.extension##index.elen * 32w8);                \
        transition nextState;                                                     \
    }

#define SNI_NAME_CHUNK(size, bitIndex, width, nextState)                          \
    state parse_name_##size {                                                     \
        transition select(hdr.sniHeader.nameLen[bitIndex:bitIndex]) {             \
            1w1:     take_name_##size;                                            \
            default: nextState;                                                   \
        }                                                                         \
    }                                                                             \
    state take_name_##size {                                                      \
        packet.extract(hdr.namePart##size);                                       \
        meta.sni = (meta.sni << width) | (bit<512>)hdr.namePart##size.value;      \
        transition nextState;                                                     \
    }

parser SwitchParser(packet_in packet,
                    out headers hdr,
                    inout metadata meta,
                    inout standard_metadata_t standard_metadata) {
    state start {
        meta.steered = 0;
        meta.ipVerdict = 0;
        meta.sniVerdict = 0;
        meta.sni = 0;
        meta.sniValid = 0;
        meta.quicFound = 0;
        meta.quicPath = PATH_NONE;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default:   accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dataOffset) {
            4w5 .. 4w15: parse_tcp_options;
            default:     accept;
        }
    }

    state parse_tcp_options {
        packet.extract(hdr.tcpOptions, (bit<32>)(hdr.tcp.dataOffset - 4w5) * 32w32);
        transition select(hdr.tcp.dstPort) {
            PORT_TLS: parse_tls;
            default:  accept;
        }
    }

    state parse_tls {
        packet.extract(hdr.tls);
        transition select(hdr.tls.contentType) {
            TLS_HANDSHAKE: parse_hello;
            default:       accept;
        }
    }

    state parse_hello {
        packet.extract(hdr.hello);
        transition select(hdr.hello.handshakeType) {
            TLS_CLIENT_HELLO: parse_session;
            default:          accept;
        }
    }

    state parse_session {
        packet.extract(hdr.sessionLen);
        transition select(hdr.sessionLen.value) {
            8w0 .. MAX_SESSION_ID: parse_session_id;
            default:               accept;
        }
    }

    state parse_session_id {
        packet.extract(hdr.sessionId, (bit<32>)hdr.sessionLen.value * 32w8);
        transition parse_ciphers;
    }

    state parse_ciphers {
        packet.extract(hdr.cipherLen);
        transition select(hdr.cipherLen.value) {
            16w0 .. MAX_CIPHERS: parse_cipher_list;
            default:             accept;
        }
    }

    state parse_cipher_list {
        packet.extract(hdr.ciphers, (bit<32>)hdr.cipherLen.value * 32w8);
        transition parse_compressions;
    }

    state parse_compressions {
        packet.extract(hdr.compressionLen);
        transition select(hdr.compressionLen.value) {
            8w0 .. MAX_COMPRESSION: parse_compression_list;
            default:                accept;
        }
    }

    state parse_compression_list {
        packet.extract(hdr.compressions, (bit<32>)hdr.compressionLen.value * 32w8);
        transition parse_extensions_len;
    }

    state parse_extensions_len {
        packet.extract(hdr.extensionsLen);
        transition select(hdr.extensionsLen.value) {
            16w0:    accept;
            default: parse_extension_0;
        }
    }

    TLS_EXTENSION_SLOT(0, parse_extension_1)
    TLS_EXTENSION_SLOT(1, parse_extension_2)
    TLS_EXTENSION_SLOT(2, parse_extension_3)
    TLS_EXTENSION_SLOT(3, parse_extension_4)
    TLS_EXTENSION_SLOT(4, parse_extension_5)
    TLS_EXTENSION_SLOT(5, accept)

    state parse_sni {
        packet.extract(hdr.sniHeader);
        transition select(hdr.sniHeader.nameType, hdr.sniHeader.nameLen) {
            (SNI_HOST_NAME, 16w1 .. MAX_SNI_NAME): parse_name_32;
            default:                               accept;
        }
    }

    SNI_NAME_CHUNK(32, 5, 256, parse_name_16)
    SNI_NAME_CHUNK(16, 4, 128, parse_name_8)
    SNI_NAME_CHUNK(8,  3, 64,  parse_name_4)
    SNI_NAME_CHUNK(4,  2, 32,  parse_name_2)
    SNI_NAME_CHUNK(2,  1, 16,  parse_name_1)
    SNI_NAME_CHUNK(1,  0, 8,   sni_done)

    state sni_done {
        meta.sniValid = 1;
        transition accept;
    }
}

control SwitchVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control SwitchIngress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    counter(10, CounterType.packets_and_bytes) stats;

    QuicSni(QUIC_TIMEOUT_MS, QUIC_MAX_FLOWS, QUIC_MAX_CRYPTO,
            (bit<32>)MAX_SNI_NAME) quicSni;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dmac, macAddr_t smac, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.dstAddr = dmac;
        hdr.ethernet.srcAddr = smac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; }
        default_action = drop();
        const entries = {
            32w0x0a000100 &&& 32w0xffffff00 :
                ipv4_forward(48w0x00000000010a, 48w0x0000000001fe, PORT_CLIENT);
            32w0x0a000200 &&& 32w0xffffff00 :
                ipv4_forward(48w0x00000000020a, 48w0x0000000002fe, PORT_SERVER);
            32w0x0a000300 &&& 32w0xffffff00 :
                ipv4_forward(MAC_MITM, MAC_MITM_GW, PORT_MITM);
            32w0x00000000 &&& 32w0x00000000 :
                ipv4_forward(48w0x00000000020a, 48w0x0000000002fe, PORT_SERVER);
        }
    }

    action via_mitm() {
        standard_metadata.egress_spec = PORT_MITM;
        hdr.ethernet.dstAddr = MAC_MITM;
        hdr.ethernet.srcAddr = MAC_MITM_GW;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.steered = 1;
    }

    action ip_block() {
        meta.ipVerdict = VERDICT_BLOCK;
    }

    action ip_white() {
        meta.ipVerdict = VERDICT_WHITE;
    }

    table ip_policy {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ip_block; ip_white; NoAction; }
        size = 512;
        default_action = NoAction();
    }

    action sni_block() {
        meta.sniVerdict = VERDICT_BLOCK;
    }

    action sni_white() {
        meta.sniVerdict = VERDICT_WHITE;
    }

    table sni_policy {
        key = { meta.sni: ternary; }
        actions = { sni_block; sni_white; NoAction; }
        size = 512;
        default_action = NoAction();
    }

    apply {
        if (!hdr.ipv4.isValid() || hdr.ipv4.ttl <= 1) {
            drop();
            return;
        }

        bool quic = hdr.udp.isValid()
            && (hdr.udp.dstPort == PORT_TLS || hdr.udp.srcPort == PORT_TLS);
        bool infra = hdr.ipv4.protocol == PROTO_ICMP
            || (hdr.udp.isValid() && (hdr.udp.dstPort == PORT_DNS
                                      || hdr.udp.srcPort == PORT_DNS));

        if (!hdr.tcp.isValid() && !quic && !infra) {
            stats.count(STAT_DENIED);
            drop();
            return;
        }

        ip_policy.apply();
        if (meta.ipVerdict == VERDICT_BLOCK) {
            stats.count(STAT_IP_BLOCKED);
            drop();
            return;
        }

        bool fromClient = standard_metadata.ingress_port == PORT_CLIENT && !infra;
        bool quicClient = fromClient && quic && hdr.udp.dstPort == PORT_TLS
            && meta.ipVerdict != VERDICT_WHITE;

        if (quicClient) {
            quicSni.classify(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                             hdr.udp.srcPort, hdr.udp.dstPort, hdr.udp.length,
                             meta.sni, meta.quicFound, meta.quicPath);
        }

        if (meta.sniValid == 1) {
            stats.count(STAT_SNI_SEEN);
        } else if (meta.quicFound == 1) {
            stats.count(STAT_QUIC_SNI);
        }

        if (meta.sniValid == 1 || meta.quicFound == 1) {
            sni_policy.apply();
        }

        if (meta.sniValid == 1 && meta.sniVerdict == VERDICT_BLOCK) {
            stats.count(STAT_SNI_BLOCKED);
            drop();
            return;
        }

        if (quicClient) {
            if (meta.quicPath == PATH_NONE) {
                if (meta.sniVerdict == VERDICT_BLOCK) {
                    meta.quicPath = PATH_BLOCK;
                } else if (meta.sniVerdict == VERDICT_WHITE) {
                    meta.quicPath = PATH_DIRECT;
                } else {
                    meta.quicPath = PATH_PROXY;
                }
                quicSni.pin(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                            hdr.udp.srcPort, hdr.udp.dstPort, meta.quicPath);
            } else if (meta.sniVerdict == VERDICT_BLOCK
                       && meta.quicPath != PATH_BLOCK) {
                meta.quicPath = PATH_BLOCK;
                quicSni.pin(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                            hdr.udp.srcPort, hdr.udp.dstPort, PATH_BLOCK);
            }

            if (meta.quicPath == PATH_BLOCK) {
                stats.count(STAT_QUIC_BLOCKED);
                drop();
                return;
            }
        }

        if (meta.ipVerdict == VERDICT_WHITE) {
            stats.count(STAT_IP_WHITE);
        } else if (fromClient) {
            if (quic) {
                if (meta.quicPath == PATH_DIRECT) {
                    stats.count(STAT_QUIC_WHITE);
                } else {
                    stats.count(STAT_QUIC);
                    via_mitm();
                }
            } else if (meta.sniVerdict == VERDICT_WHITE) {
                stats.count(STAT_SNI_WHITE);
                via_mitm();
            } else {
                via_mitm();
            }
        }

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
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.tcpOptions);
        packet.emit(hdr.tls);
        packet.emit(hdr.hello);
        packet.emit(hdr.sessionLen);
        packet.emit(hdr.sessionId);
        packet.emit(hdr.cipherLen);
        packet.emit(hdr.ciphers);
        packet.emit(hdr.compressionLen);
        packet.emit(hdr.compressions);
        packet.emit(hdr.extensionsLen);
        packet.emit(hdr.extension0);
        packet.emit(hdr.extensionBody0);
        packet.emit(hdr.extension1);
        packet.emit(hdr.extensionBody1);
        packet.emit(hdr.extension2);
        packet.emit(hdr.extensionBody2);
        packet.emit(hdr.extension3);
        packet.emit(hdr.extensionBody3);
        packet.emit(hdr.extension4);
        packet.emit(hdr.extensionBody4);
        packet.emit(hdr.extension5);
        packet.emit(hdr.extensionBody5);
        packet.emit(hdr.sniHeader);
        packet.emit(hdr.namePart32);
        packet.emit(hdr.namePart16);
        packet.emit(hdr.namePart8);
        packet.emit(hdr.namePart4);
        packet.emit(hdr.namePart2);
        packet.emit(hdr.namePart1);
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
