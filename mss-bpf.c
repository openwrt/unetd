// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2021 Felix Fietkau <nbd@nbd.name>
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile static uint32_t mtu = 1420;

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int proto_is_ip(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_IP) ||
		  h_proto == bpf_htons(ETH_P_IPV6));
}

static __always_inline void *skb_ptr(struct __sk_buff *skb, __u32 offset)
{
	void *start = (void *)(unsigned long long)skb->data;

	return start + offset;
}

static __always_inline void *skb_end_ptr(struct __sk_buff *skb)
{
	return (void *)(unsigned long long)skb->data_end;
}

static __always_inline int skb_check(struct __sk_buff *skb, void *ptr)
{
	if (ptr > skb_end_ptr(skb))
		return -1;

	return 0;
}

static __always_inline int
parse_ethernet(struct __sk_buff *skb, __u32 *offset)
{
	struct ethhdr *eth;
	__u16 h_proto;
	int i;

	eth = skb_ptr(skb, *offset);
	if (skb_check(skb, eth + 1))
		return -1;

	h_proto = eth->h_proto;
	*offset += sizeof(*eth);

#pragma unroll
	for (i = 0; i < 2; i++) {
		struct vlan_hdr *vlh = skb_ptr(skb, *offset);

		if (!proto_is_vlan(h_proto))
			break;

		if (skb_check(skb, vlh + 1))
			return -1;

		h_proto = vlh->h_vlan_encapsulated_proto;
		*offset += sizeof(*vlh);
	}

	return h_proto;
}

static __always_inline int
parse_ipv4(struct __sk_buff *skb, __u32 *offset)
{
	struct iphdr *iph;
	int hdr_len;

	iph = skb_ptr(skb, *offset);
	if (skb_check(skb, iph + 1))
		return -1;

	hdr_len = iph->ihl * 4;
	if (bpf_skb_pull_data(skb, *offset + hdr_len + sizeof(struct tcphdr) + 20))
		return -1;

	iph = skb_ptr(skb, *offset);
	*offset += hdr_len;

	if (skb_check(skb, (void *)(iph + 1)))
		return -1;

	return READ_ONCE(iph->protocol);
}

static __always_inline bool
parse_ipv6(struct __sk_buff *skb, __u32 *offset)
{
	struct ipv6hdr *iph;

	if (bpf_skb_pull_data(skb, *offset + sizeof(*iph) + sizeof(struct tcphdr) + 20))
		return -1;

	iph = skb_ptr(skb, *offset);
	*offset += sizeof(*iph);

	if (skb_check(skb, (void *)(iph + 1)))
		return -1;

	return READ_ONCE(iph->nexthdr);
}

static inline unsigned int
optlen(const u_int8_t *opt)
{
	if (opt[0] <= TCPOPT_NOP || opt[1] == 0)
		return 1;

	return opt[1];
}

static __always_inline void
fixup_tcp(struct __sk_buff *skb, __u32 offset, __u16 mss)
{
	struct tcphdr *tcph;
	__u16 oldmss;
	__u8 *opt;
	u8 flags;
	int hdrlen;
	int i;

	tcph = skb_ptr(skb, offset);
	if (skb_check(skb, tcph + 1))
		return;

	flags = tcp_flag_byte(tcph);
	if (!(flags & TCPHDR_SYN))
		return;

	hdrlen = tcph->doff * 4;
	if (hdrlen <= sizeof(struct tcphdr))
		return;

	hdrlen += offset;
	offset += sizeof(*tcph);

#pragma unroll
	for (i = 0; i < 5; i++) {
		unsigned int len;

		if (offset >= hdrlen)
			return;

		opt = skb_ptr(skb, offset);
		if (skb_check(skb, opt + TCPOLEN_MSS))
			return;

		len = optlen(opt);
		offset += len;
		if (opt[0] != TCPOPT_MSS || opt[1] != TCPOLEN_MSS)
			continue;

		goto found;
	}
	return;

found:
	oldmss = (opt[2] << 8) | opt[3];
	if (oldmss <= mss)
		return;

	opt[2] = mss >> 8;
	opt[3] = mss & 0xff;
	csum_replace2(&tcph->check, bpf_htons(oldmss), bpf_htons(mss));
}

SEC("tc")
int mssfix(struct __sk_buff *skb)
{
	__u32 offset = 0;
	__u8 ipproto;
	__u16 mss;
	int type;

	type = parse_ethernet(skb, &offset);
	if (type == bpf_htons(ETH_P_IP))
		type = parse_ipv4(skb, &offset);
	else if (type == bpf_htons(ETH_P_IPV6))
		type = parse_ipv6(skb, &offset);
	else
		return TC_ACT_UNSPEC;

	if (type != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	mss = mtu;
	mss -= offset + sizeof(struct tcphdr);
	fixup_tcp(skb, offset, mss);

	return TC_ACT_UNSPEC;
}
