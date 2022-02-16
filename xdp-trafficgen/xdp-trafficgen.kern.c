/* SPDX-License-Identifier: GPL-2.0 */

#define XDP_STATS_MAP_PINNING LIBBPF_PIN_NONE

#include "xdp-trafficgen.h"
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <xdp/xdp_stats_kern_user.h>
#include <xdp/xdp_stats_kern.h>
#include <xdp/parsing_helpers.h>

char _license[] SEC("license") = "GPL";

const volatile struct trafficgen_config config;
struct trafficgen_state state;

SEC("xdp")
int xdp_redirect_notouch(struct xdp_md *ctx)
{
	return xdp_stats_record_action(ctx, bpf_redirect(config.ifindex_out, 0));
}

SEC("xdp")
int xdp_redirect_update_port(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u16 cur_port, cksum_diff;
	int action = XDP_ABORTED;
	struct udphdr *hdr;

	hdr = data + (sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	if (hdr + 1 > data_end)
		goto out;

	cur_port = bpf_ntohs(hdr->dest);
	cksum_diff = state.next_port - cur_port;
	if (cksum_diff) {
		hdr->check = bpf_htons(~(~bpf_ntohs(hdr->check) + cksum_diff));
		hdr->dest = bpf_htons(state.next_port);
	}
	if (state.next_port++ >= config.port_start + config.port_range - 1)
		state.next_port = config.port_start;

	action = bpf_redirect(config.ifindex_out, 0);
out:
	return xdp_stats_record_action(ctx, action);
}

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, struct tcp_flowkey);
	__type(value, struct tcp_flowstate);
} flow_state_map SEC(".maps");

static int cmp_ipaddr(struct in6_addr *a_, struct in6_addr *b_)
{
	__u8 *a = (void *)a_, *b = (void *)b_;
	int i;

	for (i = 0; i < sizeof(struct in6_addr); i++) {
		if (*a > *b)
			return -1;
		if (*a < *b)
			return 1;
		a++;
		b++;
	}
	return 0;
}


SEC("xdp")
int xdp_handle_tcp_recv(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct tcp_flowstate *fstate, new_fstate = {};
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh = { .pos = data };
	struct tcp_flowkey key = {};
	int eth_type, ip_type, err;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	int action = XDP_PASS;
	struct ethhdr *eth;
	__u8 new_match;
	int i;

	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type != bpf_htons(ETH_P_IPV6))
		goto out;

	ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
	if (ip_type != IPPROTO_TCP)
		goto out;

	if (parse_tcphdr(&nh, data_end, &tcphdr) < 0)
		goto out;

	/* swap dst and src for received packet */
	key.dst_ip = ipv6hdr->saddr;
	key.dst_port = tcphdr->source;

	new_match = !cmp_ipaddr(&key.dst_ip, &state.flow_key.dst_ip) && key.dst_port == state.flow_key.dst_port;

	key.src_ip = ipv6hdr->daddr;
	key.src_port = tcphdr->dest;

	fstate = bpf_map_lookup_elem(&flow_state_map, &key);
	if (!fstate) {
		if (!new_match)
			goto out;

		new_fstate.flow_state = FLOW_STATE_NEW;
		new_fstate.seq = bpf_ntohl(tcphdr->ack_seq);
		for (i = 0; i < ETH_ALEN; i++) {
			new_fstate.dst_mac[i] = eth->h_source[i];
			new_fstate.src_mac[i] = eth->h_dest[i];
		}

		err = bpf_map_update_elem(&flow_state_map, &key, &new_fstate, BPF_NOEXIST);
		if (err)
			goto out;

		fstate = bpf_map_lookup_elem(&flow_state_map, &key);
		if (!fstate)
			goto out;
	}

	bpf_printk("Got state seq %u ack_seq %u new %u seq %u new %u window %u\n",
		   fstate->seq,
		   fstate->ack_seq, bpf_ntohl(tcphdr->ack_seq),
		   fstate->rcv_seq, bpf_ntohl(tcphdr->seq), bpf_htons(tcphdr->window));

	fstate->window = bpf_ntohs(tcphdr->window);
	fstate->ack_seq = bpf_ntohl(tcphdr->ack_seq);
	fstate->rcv_seq = bpf_ntohl(tcphdr->seq);
	if (tcphdr->syn)
		fstate->rcv_seq++;

	/* If we've taken over the flow management, (after the handshake), drop
	 * the packet
	 */
	if (fstate->flow_state == FLOW_STATE_RUNNING)
		action = XDP_DROP;
out:
	return action;
}

SEC("xdp")
int xdp_redirect_send_tcp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct tcp_flowstate *fstate;
	__u32 cur_seq, cksum_diff;
	int action = XDP_ABORTED;
	struct ipv6hdr *ipv6hdr;
	struct tcphdr *tcphdr;
	__u16 pkt_len;

	ipv6hdr = data + sizeof(struct ethhdr);
	tcphdr = data + (sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
	if (tcphdr + 1 > data_end || ipv6hdr + 1 > data_end)
		goto out;

	fstate = bpf_map_lookup_elem(&flow_state_map, (const void *)&state.flow_key);
	if (!fstate)
		goto out;

	pkt_len = bpf_ntohs(ipv6hdr->payload_len) - sizeof(*tcphdr);
	if (fstate->seq + pkt_len > fstate->ack_seq + (fstate->window << fstate->wscale)) {
		/* We caught up to the end up the RWIN, spin until ACKs come
		 * back opening up the window
		 */
		bpf_printk("Dropping: %u + %u > %u + %u\n", fstate->seq, pkt_len, fstate->ack_seq, (fstate->window << fstate->wscale));
		action = XDP_DROP;
		goto out;
	}

	cur_seq = bpf_ntohl(tcphdr->seq);
	cksum_diff = fstate->seq - cur_seq;
	if (cksum_diff) {
		tcphdr->check = bpf_htons(~(~bpf_ntohs(tcphdr->check) + cksum_diff));
		tcphdr->seq = bpf_htonl(fstate->seq);
	}
	fstate->seq += pkt_len;

	action = bpf_redirect(config.ifindex_out, 0);
out:
	return xdp_stats_record_action(ctx, action);
}
