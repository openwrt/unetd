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
#include "bpf_skb_utils.h"

const volatile static uint32_t mtu = 1420;

static __always_inline unsigned int
optlen(const u_int8_t *opt)
{
	if (opt[0] <= TCPOPT_NOP || opt[1] == 0)
		return 1;

	return opt[1];
}

static __always_inline void
fixup_tcp(struct skb_parser_info *info, __u16 mss)
{
	struct tcphdr *tcph;
	__u32 end, offset = info->offset + sizeof(*tcph);
	__u16 oldmss;
	__u8 flags;
	__u8 *opt;
	int i;

	tcph = skb_parse_tcp(info);
	if (!tcph)
		return;

	flags = tcp_flag_byte(tcph);
	if (!(flags & TCPHDR_SYN))
		return;

	end = info->offset;

#pragma unroll
	for (i = 0; i < 5; i++) {
		if (offset + 4 > end)
			return;

		opt = skb_ptr(info->skb, offset, 4);
		if (!opt)
			return;

		offset += optlen(opt);
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
	struct skb_parser_info info;
	__u16 mss;
	int type;

	skb_parse_init(&info, skb);
	if (!skb_parse_ethernet(&info))
		return TC_ACT_UNSPEC;

	skb_parse_vlan(&info);
	skb_parse_vlan(&info);

	if (!skb_parse_ipv4(&info, 60) && !skb_parse_ipv6(&info, 60))
		return TC_ACT_UNSPEC;

	if (info.proto != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	mss = mtu;
	mss -= info.offset + sizeof(struct tcphdr);
	fixup_tcp(&info, mss);

	return TC_ACT_UNSPEC;
}
