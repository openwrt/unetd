// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include "unetd.h"

static int
wg_dummy_init(struct network *net)
{
	char key[B64_ENCODE_LEN(CURVE25519_KEY_SIZE)];

	fprintf(stderr, "Create wireguard interface %s\n", network_name(net));
	b64_encode(net->config.key, sizeof(net->config.key), key, sizeof(key));
	fprintf(stderr, "key=%s\n", key);
	b64_encode(net->config.pubkey, sizeof(net->config.pubkey), key, sizeof(key));
	fprintf(stderr, "pubkey=%s\n", key);
	fprintf(stderr, "\n");

	return 0;
}

static void
wg_dummy_cleanup(struct network *net)
{
	fprintf(stderr, "Remove wireguard interface %s\n", network_name(net));
}

static int
wg_dummy_init_local(struct network *net, struct network_peer *peer)
{
	char addr[INET6_ADDRSTRLEN];

	fprintf(stderr, "local node %s, port: %d\n", network_peer_name(peer), peer->port);

	fprintf(stderr, "default addr: %s\n",
		inet_ntop(AF_INET6, &peer->local_addr.in6, addr, sizeof(addr)));

	fprintf(stderr, "\n");

	return 0;
}

static int
wg_dummy_peer_update(struct network *net, struct network_peer *peer, enum wg_update_cmd cmd)
{
	static const char * const cmds[] = {
		[WG_PEER_CREATE] = "create",
		[WG_PEER_UPDATE] = "update",
		[WG_PEER_DELETE] = "delete",
	};
	char key[B64_ENCODE_LEN(CURVE25519_KEY_SIZE)];
	char addr[INET6_ADDRSTRLEN];
	struct blob_attr *cur;
	int rem;

	b64_encode(peer->key, sizeof(peer->key), key, sizeof(key));
	fprintf(stderr, "%s peer %s: %s\n", cmds[cmd], network_peer_name(peer), key);

	if (cmd == WG_PEER_DELETE)
		return 0;

	fprintf(stderr, "default addr: %s\n",
		inet_ntop(AF_INET6, &peer->local_addr.in6, addr, sizeof(addr)));

	blobmsg_for_each_attr(cur, peer->ipaddr, rem) {
		fprintf(stderr, "peer addr: %s\n", blobmsg_get_string(cur));
	}
	blobmsg_for_each_attr(cur, peer->subnet, rem) {
		fprintf(stderr, "peer subnet: %s\n", blobmsg_get_string(cur));
	}
	fprintf(stderr, "\n");
	return 0;
}

static int
wg_dummy_peer_refresh(struct network *net)
{
	struct network_host *host;

	avl_for_each_element(&net->hosts, host, node) {
		struct network_peer *peer = &host->peer;

		if (peer->state.endpoint.in.sin_family)
			peer->state.connected = true;
	}

	return 0;
}

static int
wg_dummy_peer_connect(struct network *net, struct network_peer *peer,
		      union network_endpoint *ep)
{
	char addr[INET6_ADDRSTRLEN];
	void *ip;

	if (ep->in.sin_family == AF_INET6)
		ip = &ep->in6.sin6_addr;
	else
		ip = &ep->in.sin_addr;

	fprintf(stderr, "connect to host %s at %s:%d\n", network_peer_name(peer),
		inet_ntop(ep->in.sin_family, ip, addr, sizeof(addr)), ntohs(ep->in.sin_port));
	memcpy(&peer->state.endpoint, ep, sizeof(peer->state.endpoint));

	return 0;
}

const struct wg_ops wg_dummy_ops = {
	.name = "dummy",
	.init = wg_dummy_init,
	.cleanup = wg_dummy_cleanup,
	.init_local = wg_dummy_init_local,
	.peer_update = wg_dummy_peer_update,
	.peer_refresh = wg_dummy_peer_refresh,
	.peer_connect = wg_dummy_peer_connect,
};
