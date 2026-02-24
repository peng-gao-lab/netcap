#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <uapi/linux/ptrace.h>
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wtautological-compare"
#include <net/sock.h>
#pragma clang diagnostic pop
#include <net/inet_sock.h>
#include <net/net_namespace.h>
#include <bcc/proto.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/in6.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/bpf.h>
#include <uapi/linux/ptrace.h>
#include <net/tcp.h>


#define IP_TCP 6

//####################################################################
//
//egress handling
//
//####################################################################

struct client_key_t {
    __u32 ip;    
    __u16 port;  
} __attribute__((packed));

BPF_HASH(tagged_port, struct client_key_t, __u8);


int handle_egress(struct __sk_buff * skb) {
  void * data_end = (void * )(long) skb -> data_end;
  void * data = (void * )(long) skb -> data;
  struct ethhdr * eth = data, eth_copy;
  struct iphdr * iph, iph_copy;
  struct tcphdr * tcph, tcph_copy;

  // u32 pid = bpf_get_current_pid_tgid() >> 32;
  // bpf_trace_printk("eth1 proto 1  %s\\n", bpf_ntohs(eth->h_proto));
  if (data + sizeof( * eth) > data_end)
    return TC_ACT_OK;

  if (bpf_ntohs(eth -> h_proto) != ETH_P_IP)
    return TC_ACT_OK;

  if (data + sizeof( * eth) + sizeof( * iph) > data_end)
    return TC_ACT_OK;

  iph = data + sizeof( * eth);

  if (iph -> protocol == IP_TCP) {
    if (data + sizeof( * eth) + sizeof( * iph) + sizeof( * tcph) > data_end)
      return TC_ACT_OK;

    tcph = data + sizeof( * eth) + sizeof( * iph);

    if (tcph != 0) {
      __u32 dip = iph->daddr; 
      __u16 dport = bpf_ntohs(tcph->dest);

      struct client_key_t k = {
          .ip   = dip,
          .port = dport,
      };

      __u8 *state = tagged_port.lookup(&k);
      if (!state)
          return TC_ACT_OK;

      if (*state == 0) {
          tcph->res1 |= 0x1;
          tagged_port.delete(&k);
      }

      return TC_ACT_OK;
    }
  }

  return TC_ACT_OK;

}