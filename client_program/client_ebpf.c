#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <bcc/proto.h>
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <net/tcp.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
// #include <netinet/in.h>

#define CAP_THRESHOLD 2000000000

struct packed_capability {
    __u8 data[24];
};

BPF_HASH(time, u16, u64);
BPF_HASH(cap_map, uint32_t, struct packed_capability, 50000);
BPF_ARRAY(tagged_port, struct packed_capability, 65535);

// ####################################################################
//
// ingress handling
//
// ####################################################################

#define IP_TCP 6

static __always_inline __u32 mix32(__u32 x) {
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static __always_inline __u32 cap_key_hash(__u16 pid, __u32 dip, __u16 dport) {
    __u32 a = ((__u32)pid << 16) | dport;
    __u32 h = a ^ dip;
    return mix32(h);
}

int handle_ingress(struct xdp_md* ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct ethhdr *eth = data, eth_copy;
    struct iphdr *iph, iph_copy;
    struct tcphdr *tcph, tcph_copy;
    struct packed_capability *caph, caph_copy;

    if (data + sizeof(*eth) > data_end) return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    if (data + sizeof(*eth) + sizeof(*iph) > data_end) return XDP_PASS;

    iph = data + sizeof(*eth);

    if (iph->protocol == IP_TCP) {
        if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
            return XDP_PASS;

        tcph = data + sizeof(*eth) + sizeof(*iph);

        // u16 dstport = ntohs(tcph->source);
        // u64 ts = bpf_ktime_get_ns();
        // time.update(&dstport, &ts);

        // 0x0080 is converted to little endian 0x8000
        if (iph->frag_off & 0x0080) {
            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
                return XDP_PASS;

            if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) +
                    sizeof(*caph) >
                data_end)
                return XDP_PASS;

            caph = data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph);

            __builtin_memcpy(&caph_copy, caph, sizeof(caph_copy));

            int source_port = ntohs(tcph->source);
            if (source_port != 0) {
                __u16 incoming_pid =
                    ((__u16)caph_copy.data[18] << 8) | caph_copy.data[19];

                caph_copy.data[20] = (caph_copy.data[20] & 0x0F) |
                                     (1 << 4);  // store with type 01
                __u16 pid = incoming_pid;
                __u32 dip = iph->daddr;
                __u16 dport = bpf_ntohs(tcph->dest);

                __u32 h = cap_key_hash(pid, dip, dport);
                cap_map.update(&h, &caph_copy);

                tagged_port.update(&source_port, &caph_copy);

                // send ack to switch
                caph_copy.data[20] = (caph_copy.data[20] & 0x0F) |
                                     (2 << 4);  // send with type 03
                __u32 temp_address = iph->saddr;
                iph->saddr = iph->daddr;
                iph->daddr = temp_address;
                return XDP_TX;
            }

            // bpf_trace_printk("DROPPED XDP PACKET\\n");
            return XDP_DROP;
        }
        return XDP_PASS;
    }
    return XDP_PASS;
}

// ####################################################################
//
// Incoming active tcp tracing
//
// ####################################################################

BPF_HASH(currsock, u32, struct sock*);

int trace_tcp_v4_connect_entry(struct pt_regs* ctx, struct sock* sk,
                               int addr_len) {
    u32 pid = bpf_get_current_pid_tgid();
    currsock.update(&pid, &sk);

    return 0;
};

int kretprobe__inet_hash_connect(struct pt_regs* ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    int ret = PT_REGS_RC(ctx);

    struct sock** skpp;
    skpp = currsock.lookup(&pid);
    if (skpp == 0) {
        return 0;  // missed entry
    }

    if (ret != 0) {
        // failed to send SYNC packet, may not have populated
        // socket __sk_common.{skc_rcv_saddr, ...}
        currsock.delete(&pid);
        return 0;
    }

    // pull in details
    struct sock* skp = *skpp;
    struct inet_sock* sockp = (struct inet_sock*)skp;
    int sport = sockp->inet_sport;
    sport = ntohs(sport);
    __u32 dest_ip = sockp->inet_daddr;
    __u16 dport_h = bpf_ntohs(sockp->inet_dport);

    __u32 h = cap_key_hash(pid, dest_ip, dport_h);

    struct packed_capability* cap = cap_map.lookup(&h);

    if (cap != 0) {
        struct packed_capability cap_copy;
        __builtin_memcpy(&cap_copy, cap, sizeof(cap_copy));
        tagged_port.update(&sport, &cap_copy);
    }
    currsock.delete(&pid);
    return 0;
}

// ####################################################################
//
// egress handling
//
// ####################################################################

#define MAX_UDP_SIZE 1480

__attribute__((__always_inline__)) static inline __u16 caltcpcsum(
    struct iphdr* iph, struct tcphdr* tcph, void* data_end) {
    __u32 csum_buffer = 0;
    __u16* buf = (void*)tcph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    unsigned short tcpLen = ntohs(iph->tot_len) - (iph->ihl << 2);

    csum_buffer += htons(tcpLen);

    // Compute checksum on udp header + payload
    // bpf_trace_printk("COMPUTING BUFF = ");
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) {
        if ((void*)(buf + 1) > data_end) {
            break;
        }
        // bpf_trace_printk("%x", * buf);
        csum_buffer += *buf;
        buf++;
    }

    if ((void*)buf + 1 <= data_end) {
        csum_buffer += *(__u8*)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;
    return csum;
}

static __always_inline __u16 csum_fold_helper(__u32 csum) {
    csum = ((csum & 0xffff) + (csum >> 16));
    return ~((csum & 0xffff) + (csum >> 16));
}

#define PROCESS_CSUM_DIFF_CHUNK(skb, csum, offset, temp_data_buf,            \
                                remaining_len, ret, chunk_size_bytes,        \
                                err_msg_case_id)                             \
    ret = bpf_skb_load_bytes(skb, offset, temp_data_buf, chunk_size_bytes);  \
    if (ret < 0) {                                                           \
        return ret;                                                          \
    }                                                                        \
    csum =                                                                   \
        bpf_csum_diff(0, 0, (__be32*)temp_data_buf, chunk_size_bytes, csum); \
    remaining_len -= chunk_size_bytes;                                       \
    offset += chunk_size_bytes

static __always_inline int skb_variable_length_csum_diff(struct __sk_buff* skb,
                                                         __u8* start, __u16 len,
                                                         __u32* csum) {
    int ret;
    __u8 buf[128];

    __u32 offset = start - (__u8*)((long)skb->data);
    if (len >= 1024) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 1024);
    }
    if (len >= 512) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 512);
    }
    if (len >= 256) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 256);
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 256);
    }
    if (len >= 128) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 128, 128);
    }
    if (len >= 64) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 64, 64);
    }
    if (len >= 32) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 32, 32);
    }
    if (len >= 16) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 16, 16);
    }
    if (len >= 8) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 8, 8);
    }
    if (len >= 4) {
        PROCESS_CSUM_DIFF_CHUNK(skb, *csum, offset, buf, len, ret, 4, 4);
    }
    if (len > 0) {
        buf[0] = 0;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        if (len >= 2) {
            ret = bpf_skb_load_bytes(skb, offset, buf, 2);
            if (ret < 0) {
                // bpf_printk(
                // "Failed (%d) to bpf_skb_load_bytes with offset=%d #2\n",
                // ret, offset);
                return ret;
            }
            len -= 2;
            offset += 2;
        }
        if (len >= 1) {
            ret = bpf_skb_load_bytes(skb, offset, buf, 1);
            if (ret < 0) {
                // bpf_printk(
                // "Failed (%d) to bpf_skb_load_bytes with offset=%d #1\n",
                // ret, offset);
                return ret;
            }
            len -= 1;
            offset += 1;
        }
        *csum = bpf_csum_diff(0, 0, (__be32*)buf, 4, *csum);
    }
    return 0;
}

BPF_ARRAY(port_cap_ts, u64, 65535);

struct chaskey_hdr {
    __u32 v0;
    __u32 v1;
    __u32 v2;
    __u32 v3;
} __attribute__((packed));
static __always_inline __u32 load_be32(const __u8* p) {
    return ((__u32)p[0] << 24) | ((__u32)p[1] << 16) | ((__u32)p[2] << 8) |
           ((__u32)p[3]);
}

static __always_inline __u16 load_be16(const __u8* p) {
    return ((__u16)p[0] << 8) | ((__u16)p[1]);
}

static __always_inline void build_empty_cap(struct packed_capability* cap,
                                            __u16 pid16) {
    // all zeros by default
    __builtin_memset(cap, 0, sizeof(*cap));
    cap->data[18] = (__u8)(pid16 >> 8);
    cap->data[19] = (__u8)(pid16 & 0xff);
}

int handle_egress(struct __sk_buff* skb) {
    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;

    struct ethhdr* eth = data;
    struct iphdr* iph;

    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return TC_ACT_OK;
    if (data + sizeof(*eth) + sizeof(struct iphdr) > data_end) return TC_ACT_OK;

    iph = data + sizeof(*eth);
    if (iph->protocol != IP_TCP) return TC_ACT_OK;

    // Read PID =
    __u16 pid16 = (__u16)(bpf_get_current_pid_tgid() >> 32);

    struct iphdr iph_orig;
    long ret = bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph_orig,
                                  sizeof(iph_orig));
    if (ret) return TC_ACT_OK;

    __u32 ip_hlen = iph_orig.ihl * 4;
    if (ip_hlen < sizeof(struct iphdr) || ip_hlen > 60) return TC_ACT_OK;

    iph_orig.check = bpf_htons(pid16);

    ret = bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_orig,
                              sizeof(iph_orig), 0);
    if (ret) return TC_ACT_OK;

    __u16 sport_be = 0;
int tcp_off = sizeof(struct ethhdr) + ip_hlen;

ret = bpf_skb_load_bytes(skb, tcp_off, &sport_be, sizeof(sport_be));
if (ret) goto out_restore_original;

int sport = bpf_ntohs(sport_be);

    struct packed_capability cap_to_send;
    struct packed_capability* chdr = tagged_port.lookup(&sport);

    if (chdr) {
        __builtin_memcpy(&cap_to_send, chdr, sizeof(cap_to_send));
    } else {
        build_empty_cap(&cap_to_send, pid16);
    }

    struct tcphdr tcph_copy;
    ret = bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + ip_hlen, &tcph_copy,
                             sizeof(tcph_copy));
    if (ret) goto out_restore_original;

    ret = bpf_skb_adjust_room(skb, 24, BPF_ADJ_ROOM_NET,
                              BPF_F_ADJ_ROOM_FIXED_GSO);
    if (ret) goto out_restore_original;

    // Restore TCP header back
    int off = sizeof(struct ethhdr) + ip_hlen;
    ret = bpf_skb_store_bytes(skb, off, &tcph_copy, sizeof(tcph_copy), 0);
    if (ret) goto out_shrink;

    // Store CAP after TCP header
    off += sizeof(tcph_copy);
    ret = bpf_skb_store_bytes(skb, off, &cap_to_send, sizeof(cap_to_send), 0);
    if (ret) goto out_shrink;

    struct iphdr iph_cap = iph_orig;
    iph_cap.frag_off = iph_cap.frag_off | bpf_htons(0x0080);
    (void)bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_cap,
                              sizeof(iph_cap), 0);
    bpf_clone_redirect(skb, skb->ifindex, 0);

out_shrink:
    // Undo insertion so original continues without CAP
    (void)bpf_skb_adjust_room(skb, -24, BPF_ADJ_ROOM_NET,
                              BPF_F_ADJ_ROOM_FIXED_GSO);

out_restore_original:
    // Restore original IP header
    (void)bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_orig,
                              sizeof(iph_orig), 0);

    return TC_ACT_OK;
}