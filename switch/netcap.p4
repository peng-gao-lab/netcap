/*******************************************************************************
 * BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
 *
 * Copyright (c) 2019-present Barefoot Networks, Inc.
 *
 * All Rights Reserved.
 *
 * NOTICE: All information contained herein is, and remains the property of
 * Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
 * technical concepts contained herein are proprietary to Barefoot Networks, Inc.
 * and its suppliers and may be covered by U.S. and Foreign Patents, patents in
 * process, and are protected by trade secret or copyright law.  Dissemination of
 * this information or reproduction of this material is strictly forbidden unless
 * prior written permission is obtained from Barefoot Networks, Inc.
 *
 * No warranty, explicit or implicit is provided, unless granted under a written
 * agreement with Barefoot Networks, Inc.
 *
 ******************************************************************************/


#include <t2na.p4>
#include "chaskey8.p4"

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

//caps data types
typedef bit<128> cap_t;
typedef bit<16> tstamp_t;
typedef bit<32> key_t;
typedef bit<16> pid_t;

typedef bit<4> dec_t;
typedef bit<4> bf_index_t;
typedef bit<1> bf_out_t;
typedef bit<16> conn_index_t;

typedef bit<16> cap_index_t;
typedef bit<32> cap_dec_index_t;

#define RECIRC_PORT 68;

//Mirroring consts
typedef bit<3> mirror_type_t;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

#define CAP_DECISION_CELLS 128 

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;

typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;

const bit<16> EVIL_BIT = 0x8000;

header ethernet_h {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16> ether_type;
}

header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags;
    // bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header cap_h {
    cap_t c;
    tstamp_t tstamp;
    pid_t pid;
    bit<4> type;
    bit<2> key_version;
    bit<2> padding1;
    bit<16> hash_value;
}

header latency_h {
    bit<64> ingress_time;
    bit<64> egress_time;
}

header tdiff_h {
    tstamp_t diff; 
}

struct header_t {
    ethernet_h ethernet;
    ipv4_h ipv4;
    tcp_h tcp;
    // latency_h latency;
    cap_h cap;
    chaskey_h chaskey;
    tdiff_h tdiff;
}


struct metadata_t {
    // bridge_h bridge_hdr;
    
    ipv4_addr_t dst_addr;
    ipv4_addr_t src_addr;
    bit<16> dst_port;
    bit<16> src_port;

    // ipv4_addr_t block_dst_addr;
    bit<1> checksum_upd_ipv4;

    bit<1> need_cap_dest;
    cap_t correct_cap_hash;

    tstamp_t tstamp_max;
    tstamp_t tstamp_diff;
    tstamp_t tstamp_check;
    tstamp_t tstamp_current_temp;
    tstamp_t tstamp_cap;

    //Secret keys
    key_t key;
    bit<2> current_key_version;

    bit<1> cap_isvalid;
    bit<1> tstamp_isvalid;
    bit<1> do_fwd;

    MirrorId_t mir_ses;
    bit<1> is_recirculated_pkt;

    bit<1> conn_flag;

    bit<16> hash_value;
    bit<16> hash_value2;

    bit<16> auth_seen;
    bit<64> block_tstamp1;
    bit<12> block_tstamp2;

    bit<12> auth_tstamp_difference;
    bit<1> auth_block_flag;

    bit<32> temp_ip;
    bit<16> temp_port;

    bit<16> cached_pid;
}

// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser TofinoIngressParser(
            packet_in pkt,
            out ingress_intrinsic_metadata_t ig_intr_md) {
        state start {
            pkt.extract(ig_intr_md);
            transition select(ig_intr_md.resubmit_flag) {
                1 : parse_resubmit;
                0 : parse_port_metadata;
            }
        }

        state parse_resubmit {
            // Parse resubmitted packet here.
            transition reject;
        }

        state parse_port_metadata {
            pkt.advance(PORT_METADATA_SIZE);
            transition accept;
        }
}
parser SwitchIngressParser(
        packet_in pkt,
        out header_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    

    state start {
        tofino_parser.apply(pkt, ig_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition select (hdr.ipv4.flags[15:15]) {
            1 : parse_cap;
            default : accept;
        }
    }

    state parse_cap {
        pkt.extract(hdr.cap);
        pkt.extract(hdr.chaskey);
        transition accept;
    }

}


// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------

control SwitchIngress(
        inout header_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {
    

    action route(bit<9> dst_port) {
        ig_intr_tm_md.ucast_egress_port = dst_port;
    }

    action miss() {
        ig_dprsr_md.drop_ctl = 0x1; // Drop packet.
    }

    table table_forward {
        key = {
            hdr.ipv4.dst_addr : exact;
            ig_md.do_fwd : exact;
        }

        actions = {
            route;
            miss;
        }

        const default_action = miss;
        size = 16;
    }

    Hash<cap_t>(HashAlgorithm_t.CRC32) cap_hash;

    action set_key(key_t key) {
        ig_md.key = key; 
    }

    table table_check_key_version {
        key = {
            hdr.cap.key_version: exact;
        }
        actions = {
            set_key;
        }
        size = 4;
    }

    //Capability decision cache
    Register<bit<1>, cap_dec_index_t> (size=CAP_DECISION_CELLS, initial_value=0) cache_cap_decision;
    //the first inout argument is the value of the Register entry being read and
    //updated, while the second optional out argument is the value that will be returned by
    //the execute method
    RegisterAction<bit<1>, cap_dec_index_t, bit<1>>(cache_cap_decision) cap_decision_get = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
        }
    };
    RegisterAction<bit<1>, cap_dec_index_t, bit<1>>(cache_cap_decision) cap_decision_set = {
        void apply(inout bit<1> value, out bit<1> read_value) {
            read_value = value;
            value = 1;
        }
    };
    Hash<cap_dec_index_t>(HashAlgorithm_t.CRC16) cap_decision_hash_get;
    Hash<cap_dec_index_t>(HashAlgorithm_t.CRC16) cap_decision_hash_set;


    action init_chaskey() {
        hdr.chaskey.curr_round = 0;
    }

    action swap_ip(){
        ipv4_addr_t tmp;
        tmp = hdr.ipv4.src_addr;
        hdr.ipv4.src_addr = hdr.ipv4.dst_addr;
        hdr.ipv4.dst_addr = tmp;
    }


    action a_recriclate(){
        ig_intr_tm_md.ucast_egress_port = RECIRC_PORT;
    }

    table t_recirculate {
        actions = { a_recriclate; }
        size = 1;
        const default_action = a_recriclate;
    }

    action compute_diff_to_tdiff() {
        hdr.tdiff.setValid();
        hdr.tdiff.diff = (tstamp_t)(ig_md.tstamp_current_temp - hdr.cap.tstamp);
    }

    ChaskeyIngress() chsk_ingress;
    
    apply {
        ig_md.tstamp_current_temp = (tstamp_t)(ig_intr_prsr_md.global_tstamp >> 32);
        if (hdr.ipv4.flags[15:15] == 1) {  
            if (hdr.cap.type == 0x0){
                hdr.chaskey.v_2[15:0] = ig_md.tstamp_current_temp;
            }
            else if (hdr.cap.type == 0x1){
                t_recirculate.apply();
            }
            else if (hdr.cap.type == 0x4){
                cap_decision_set.execute(cap_decision_hash_set.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.cap.pid}));
            }
            init_chaskey();
            chsk_ingress.apply(hdr.chaskey);
        }
        ig_md.do_fwd = cap_decision_get.execute(cap_decision_hash_get.get({hdr.ipv4.src_addr, hdr.ipv4.dst_addr, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.ipv4.hdr_checksum}));
        if(hdr.cap.type == 0x0){
            swap_ip();
            ig_md.do_fwd = (bit<1>)1;
        }
        table_forward.apply();
        


    }
}
// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout header_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    
    Checksum() ipv4_checksum;
    Mirror() mirror;

    apply {
        hdr.ipv4.hdr_checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr});

        pkt.emit(hdr);
    }
}

// ---------------------------------------------------------------------------
// Egress Parser
// ---------------------------------------------------------------------------
parser TofinoEgressParser(
        packet_in pkt,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

parser SwitchEgressParser(packet_in pkt, out header_t hdr, 
    out metadata_t eg_md, out egress_intrinsic_metadata_t eg_intr_md) {
    
    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(pkt, eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_TCP : parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        // pkt.extract(hdr.latency);
        transition select (hdr.ipv4.flags[15:15]) {
            1 : parse_cap;
            default : accept;
        }
    }

    state parse_cap {
        pkt.extract(hdr.cap);
        pkt.extract(hdr.chaskey);
        pkt.extract(hdr.tdiff);
        transition accept;
    }

}



// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
    inout header_t hdr,
	inout metadata_t eg_md,
	in egress_intrinsic_metadata_t eg_intr_md,
	in egress_intrinsic_metadata_from_parser_t eg_intr_parser_md,
	inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
	inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    action check_cap(){
		eg_md.cap_isvalid = (bit<1>)1;
	}

    table table_check_cap {
        key = { 
            hdr.chaskey.v_0: exact;
            hdr.chaskey.v_1: exact;
            hdr.chaskey.v_2: exact;
            hdr.chaskey.v_3: exact;
        }
        actions = {
            check_cap;
            NoAction;
        }
        size = 16;
        default_action = NoAction;
    }

    action calc_tstamp_diff(){ 
        eg_md.tstamp_diff = eg_md.tstamp_current_temp - (tstamp_t) hdr.chaskey.v_2;
    }

    table table_calc_tstamp_diff {
    actions = { calc_tstamp_diff; }
    size = 1;
    default_action = calc_tstamp_diff();
    }

    action set_tstamp_valid() {
        eg_md.tstamp_isvalid = (bit<1>)(eg_md.tstamp_diff <= eg_md.tstamp_max);
    }
    table table_set_tstamp_valid {
        actions = { set_tstamp_valid; }
        size = 1;
        default_action = set_tstamp_valid();
    }


    action drop() {
        eg_intr_md_for_dprsr.drop_ctl = 0x1;
    }

    action do_checks_refresh() {
        hdr.cap.type = 0x0;
    }

    action do_checks_valid() {
        hdr.cap.type = 0x4;
    }

    table table_do_checks {
        key = {
            eg_md.tstamp_isvalid: exact;
            eg_md.cap_isvalid: exact;
        }
        actions = {
            do_checks_refresh;
            do_checks_valid;
            drop;
        }
        size = 4;
        const entries = {
            ((bit<1>)0, (bit<1>)1): do_checks_refresh(); 
            ((bit<1>)1, (bit<1>)1): do_checks_valid();
        }
    }

    action set_tstamp_valid_from_tdiff() {
        eg_md.tstamp_isvalid = (bit<1>)(hdr.tdiff.diff <= eg_md.tstamp_max);
    }

    table table_set_tstamp_valid_from_tdiff {
        actions = { set_tstamp_valid_from_tdiff; }
        size = 1;
        default_action = set_tstamp_valid_from_tdiff();
    }

    ChaskeyEgress() chsk_egress;
	
    apply {
        if (hdr.ipv4.flags[15:15] == 1) {
            chsk_egress.apply(hdr.chaskey);
            table_set_tstamp_valid_from_tdiff.apply();

            if (hdr.cap.type == 0x1) {
                table_check_cap.apply();
                table_do_checks.apply();
                hdr.tdiff.setInvalid();
            }
        }

    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(packet_out packet, inout header_t hdr, in metadata_t eg_md, in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
      packet.emit(hdr);  
    }

}


Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()) pipe;

Switch(pipe) main;