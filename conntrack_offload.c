/* Copyright (C) 2018, Red Hat, Inc.
 *
 * This program is free software; you can distribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "ctfoo"

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
               char ____fmt[] = fmt;                            \
               bpf_trace_printk(____fmt, sizeof(____fmt),       \
                               ##__VA_ARGS__);                 \
})

struct bpf_map_def SEC("maps") conntrack = {
	.type = BPF_MAP_TYPE_FLOWMAP,
	.key_size = sizeof(struct bpf_flow_map),
	.value_size = sizeof(struct bpf_flow_map),
    .map_flags = BPF_MAP_CREATE,
	.max_entries = 1
};

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 100,
};

/* for now, forget 802.1q and q-in-q handling*/
static int validate_eth_ip4(struct xdp_md *ctx, struct iphdr **iphd)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;

	if (data + sizeof(*eth) > data_end)
		return 1;

	switch (ntohs(eth->h_proto)) {
	default:
        break;
    case ETH_P_IPV6:
	case ETH_P_ARP:
		return 2;
	}

	iph = data + sizeof(*eth);
	if (iph + 1 > data_end)
		return 1;

	switch (iph->protocol) {
	default:
        bpf_printk("Unknown proto: %d\n", iph->protocol);
		return 1;

    case IPPROTO_ICMP:
	case IPPROTO_UDP:
		/* fallthrough */
	case IPPROTO_TCP:
		break;
	}

	*iphd = iph;
	return 0;
}

static void build_flowmap_key(struct bpf_flow_map *m, struct iphdr *i,
			      const struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = i+1;

	m->flow.ip_proto = i->protocol;
	m->flow.ipv4_src = i->saddr;
	m->flow.ipv4_dst = i->daddr;
	m->flow.sport = 0;
	m->flow.dport = 0;
    m->ifindex = ctx->ingress_ifindex;
    m->flow.addr_proto = htons(ETH_P_IP);

	switch(i->protocol) {
	case IPPROTO_UDP:
		{
			struct udphdr *uh = (struct udphdr *)data;
			if (uh + 1 > data_end)
				return;
			m->flow.sport = uh->source;
			m->flow.dport = uh->dest;
		}
		break;
	case IPPROTO_TCP:
		{
			struct tcphdr *th = (struct tcphdr *)data;
			if (th + 1 > data_end)
				return;
			m->flow.sport = th->source;
			m->flow.dport = th->dest;
		}
		break;
	}
}

SEC("prog")
int xdp_prog1(struct xdp_md *ctx)
{
	struct bpf_flow_map k = {};
	struct bpf_flow_map *v;
	struct iphdr *iph;

	switch (validate_eth_ip4(ctx, &iph)) {
	default:
		/* fallthrough */
	case 0:
		break;

	case 1:
		return XDP_DROP;

	case 2:
        bpf_printk("arp? WtF?\n");
		return XDP_PASS;
	}

	build_flowmap_key(&k, iph, ctx);

	v = bpf_map_lookup_elem(&conntrack, &k);
	if (!v) {
        bpf_printk("No connection found...\n");
		return XDP_PASS;
    }

	bpf_printk("Found connection from dev: %d\n", ctx->ingress_ifindex);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
