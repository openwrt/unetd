// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 *
 * Based on wireguard-tools:
 *   Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */
#define _GNU_SOURCE
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <linux/wireguard.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <unl.h>

#include "unetd.h"

struct timespec64 {
	int64_t tv_sec;
	int64_t tv_nsec;
};

struct wg_linux_peer_req {
	struct nl_msg *msg;

	struct nlattr *peers, *entry;
};

static struct unl unl;

static int
wg_nl_init(void)
{
	if (unl.sock)
		return 0;

	return unl_genl_init(&unl, "wireguard");
}

static struct nl_msg *
wg_genl_msg(struct network *net, bool set)
{
	struct nl_msg *msg;

	msg = unl_genl_msg(&unl, set ? WG_CMD_SET_DEVICE : WG_CMD_GET_DEVICE, !set);
	nla_put_string(msg, WGDEVICE_A_IFNAME, network_name(net));

	return msg;
}

static int
wg_genl_call(struct nl_msg *msg)
{
	return unl_request(&unl, msg, NULL, NULL);
}

static int
__wg_linux_init(struct network *net, void *key)
{
	struct nl_msg *msg;

	msg = wg_genl_msg(net, true);
	nla_put(msg, WGDEVICE_A_PRIVATE_KEY, WG_KEY_LEN, key);
	nla_put_u32(msg, WGDEVICE_A_FLAGS, WGDEVICE_F_REPLACE_PEERS);

	return wg_genl_call(msg);
}

static void
wg_linux_cleanup(struct network *net)
{
	uint8_t key[WG_KEY_LEN] = {};

	__wg_linux_init(net, key);
}

static int
wg_linux_init(struct network *net)
{
	if (wg_nl_init())
		return -1;

	return __wg_linux_init(net, net->config.key);
}

static int
wg_linux_init_local(struct network *net, struct network_peer *peer)
{
	struct nl_msg *msg;

	msg = wg_genl_msg(net, true);
	nla_put_u16(msg, WGDEVICE_A_LISTEN_PORT, peer->port);

	return wg_genl_call(msg);
}

static void
wg_linux_msg_add_ip(struct nl_msg *msg, int af, void *addr, int mask)
{
	struct nlattr *ip;
	int len;

	if (af == AF_INET6)
		len = sizeof(struct in6_addr);
	else
		len = sizeof(struct in_addr);

	ip = nla_nest_start(msg, 0);
	nla_put_u16(msg, WGALLOWEDIP_A_FAMILY, af);
	nla_put(msg, WGALLOWEDIP_A_IPADDR, len, addr);
	nla_put_u8(msg, WGALLOWEDIP_A_CIDR_MASK, mask);
	nla_nest_end(msg, ip);
}

static struct nl_msg *
wg_linux_peer_req_init(struct network *net, struct network_peer *peer,
		       struct wg_linux_peer_req *req)
{
	req->msg = wg_genl_msg(net, true);

	req->peers = nla_nest_start(req->msg, WGDEVICE_A_PEERS);
	req->entry = nla_nest_start(req->msg, 0);
	nla_put(req->msg, WGPEER_A_PUBLIC_KEY, WG_KEY_LEN, peer->key);

	return req->msg;
}

static int
wg_linux_peer_req_done(struct wg_linux_peer_req *req)
{
	nla_nest_end(req->msg, req->entry);
	nla_nest_end(req->msg, req->peers);

	return wg_genl_call(req->msg);
}

static void
wg_linux_peer_msg_add_allowed_ip(struct nl_msg *msg, struct network_peer *peer)
{
	struct blob_attr *cur;
	int rem;

	wg_linux_msg_add_ip(msg, AF_INET6, &peer->local_addr.in6, 128);

	blobmsg_for_each_attr(cur, peer->ipaddr, rem) {
		const char *str = blobmsg_get_string(cur);
		struct in6_addr in6;
		int af, mask;

		if (strchr(str, ':')) {
			af = AF_INET6;
			mask = 128;
		} else {
			af = AF_INET;
			mask = 32;
		}

		if (inet_pton(af, str, &in6) != 1)
			continue;

		wg_linux_msg_add_ip(msg, af, &in6, mask);
	}

	blobmsg_for_each_attr(cur, peer->subnet, rem) {
		const char *str = blobmsg_get_string(cur);
		union network_addr addr;
		int mask;
		int af;

		af = strchr(str, ':') ? AF_INET6 : AF_INET;
		if (network_get_subnet(af, &addr, &mask, str))
			continue;

		wg_linux_msg_add_ip(msg, af, &addr, mask);
	}

}

static int
wg_linux_peer_update(struct network *net, struct network_peer *peer, enum wg_update_cmd cmd)
{
	struct wg_linux_peer_req req;
	struct network_host *host;
	struct nl_msg *msg;
	struct nlattr *ips;

	msg = wg_linux_peer_req_init(net, peer, &req);

	if (cmd == WG_PEER_DELETE) {
		nla_put_u32(msg, WGPEER_A_FLAGS, WGPEER_F_REMOVE_ME);
		goto out;
	}

	nla_put_u32(msg, WGPEER_A_FLAGS, WGPEER_F_REPLACE_ALLOWEDIPS);

	ips = nla_nest_start(msg, WGPEER_A_ALLOWEDIPS);

	wg_linux_peer_msg_add_allowed_ip(msg, peer);
	for_each_routed_host(host, net, peer)
		wg_linux_peer_msg_add_allowed_ip(msg, &host->peer);

	nla_nest_end(msg, ips);

out:
	return wg_linux_peer_req_done(&req);
}

static void
wg_linux_parse_peer(struct network *net, struct nlattr *data, time_t now)
{
	struct network_peer *peer = NULL;
	struct nlattr *tb[__WGPEER_A_LAST];
	struct nlattr *cur;

	nla_parse_nested(tb, WGPEER_A_MAX, data, NULL);

	cur = tb[WGPEER_A_PUBLIC_KEY];
	if (!cur)
		return;

	peer = wg_peer_update_start(net, nla_data(cur));
	if (!peer)
		return;

	if ((cur = tb[WGPEER_A_LAST_HANDSHAKE_TIME]) != NULL) {
		struct timespec64 *tv = nla_data(cur);

		wg_peer_set_last_handshake(net, peer, now, tv->tv_sec);
	}

	if ((cur = tb[WGPEER_A_RX_BYTES]) != NULL)
		wg_peer_set_rx_bytes(net, peer, nla_get_u64(cur));

	if ((cur = tb[WGPEER_A_ENDPOINT]) != NULL)
		wg_peer_set_endpoint(net, peer, nla_data(cur), nla_len(cur));

	wg_peer_update_done(net, peer);
}

static void
wg_linux_parse_peer_list(struct network *net, struct nlattr *data, time_t now)
{
	struct nlattr *cur;
	int rem;

	if (!data)
		return;

	nla_for_each_nested(cur, data, rem)
		wg_linux_parse_peer(net, cur, now);
}

static int
wg_linux_get_cb(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nh = nlmsg_hdr(msg);
	struct network *net = arg;
	struct nlattr *tb[__WGDEVICE_A_LAST];
	time_t now = time(NULL);

	nlmsg_parse(nh, sizeof(struct genlmsghdr), tb, __WGDEVICE_A_LAST, NULL);
	wg_linux_parse_peer_list(net, tb[WGDEVICE_A_PEERS], now);

	return NL_SKIP;
}

static int
wg_linux_peer_refresh(struct network *net)
{
	struct nl_msg *msg = wg_genl_msg(net, false);

	return unl_request(&unl, msg, wg_linux_get_cb, net);
}

static int
wg_linux_peer_connect(struct network *net, struct network_peer *peer,
		      union network_endpoint *ep)
{
	struct wg_linux_peer_req req;
	struct nl_msg *msg;
	int len;

	msg = wg_linux_peer_req_init(net, peer, &req);

	if (net->net_config.keepalive) {
		nla_put_u16(msg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL, 0);
		wg_linux_peer_req_done(&req);

		msg = wg_linux_peer_req_init(net, peer, &req);
		nla_put_u16(msg, WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
			    net->net_config.keepalive);
	}

	if (ep->in.sin_family == AF_INET6)
		len = sizeof(ep->in6);
	else
		len = sizeof(ep->in);
	nla_put(msg, WGPEER_A_ENDPOINT, len, &ep->in6);

	return wg_linux_peer_req_done(&req);
}

const struct wg_ops wg_linux_ops = {
	.name = "user",
	.init = wg_linux_init,
	.cleanup = wg_linux_cleanup,
	.init_local = wg_linux_init_local,
	.peer_update = wg_linux_peer_update,
	.peer_refresh = wg_linux_peer_refresh,
	.peer_connect = wg_linux_peer_connect,
};
