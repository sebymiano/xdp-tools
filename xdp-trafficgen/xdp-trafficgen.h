/* SPDX-License-Identifier: GPL-2.0 */

#ifndef XDP_TRAFFICGEN_H
#define XDP_TRAFFICGEN_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>

struct tcp_flowkey {
  struct in6_addr src_ip;
  struct in6_addr dst_ip;
  __u16 dst_port;
  __u16 src_port;
};

#define FLOW_STATE_NEW 1
#define FLOW_STATE_RUNNING 2

struct tcp_flowstate {
  __u8 dst_mac[ETH_ALEN];
  __u8 src_mac[ETH_ALEN];
  __u32 flow_state;
  __u32 seq;     /* our last sent seqno */
  __u32 ack_seq; /* last seqno that got acked */
  __u32 rcv_seq; /* receiver's seqno (our ACK seq) */
  __u16 window;
  __u8 wscale;
};

struct trafficgen_config {
  int ifindex_out;
  __u16 port_start;
  __u16 port_range;
};

struct trafficgen_state {
  struct tcp_flowkey flow_key;
  __u16 next_port;
};



#endif
