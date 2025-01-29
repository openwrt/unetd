// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#include "unetd.h"
#include "pex-msg.h"
#include "enroll.h"

static const char *pex_peer_id_str(const uint8_t *key)
{
	static char str[20];
	int i;

	for (i = 0; i < 8; i++)
		sprintf(str + i * 2, "%02x", key[i]);

	return str;
}

static struct pex_hdr *
pex_msg_init(struct network *net, uint8_t opcode)
{
	return __pex_msg_init(net->config.pubkey, opcode);
}

static struct pex_hdr *
pex_msg_init_ext(struct network *net, uint8_t opcode, bool ext)
{
	return __pex_msg_init_ext(net->config.pubkey, net->config.auth_key, opcode, ext);
}

static struct network_peer *
pex_msg_peer(struct network *net, const uint8_t *id, bool allow_indirect)
{
	struct network_peer *peer;
	uint8_t key[WG_KEY_LEN] = {};

	memcpy(key, id, PEX_ID_LEN);
	peer = avl_find_ge_element(&net->peers.avl, key, peer, node.avl);
	if (!peer || memcmp(peer->key, key, PEX_ID_LEN) != 0) {
		D_NET(net, "can't find peer %s", pex_peer_id_str(id));
		return NULL;
	}
	if (peer->indirect && !allow_indirect)
		return NULL;

	return peer;
}

static void
pex_get_peer_addr(struct sockaddr_in6 *sin6, struct network *net,
		  struct network_peer *peer)
{
	*sin6 = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_addr = peer->local_addr.in6,
		.sin6_port = htons(peer->pex_port),
	};
}

static void pex_msg_send(struct network *net, struct network_peer *peer)
{
	struct sockaddr_in6 sin6 = {};

	if (!peer || peer == &net->net_config.local_host->peer ||
	    !peer->pex_port)
		return;

	pex_get_peer_addr(&sin6, net, peer);
	if (__pex_msg_send(net->pex.fd.fd, &sin6, NULL, 0) < 0)
		D_PEER(net, peer, "pex_msg_send failed: %s", strerror(errno));
}

static void pex_msg_send_ext(struct network *net, struct network_peer *peer,
			     struct sockaddr_in6 *addr)
{
	char addrbuf[INET6_ADDRSTRLEN];

	if (!addr)
		return pex_msg_send(net, peer);

	if (__pex_msg_send(-1, addr, NULL, 0) < 0)
		D_NET(net, "pex_msg_send_ext(%s) failed: %s",
		      inet_ntop(addr->sin6_family, (const void *)&addr->sin6_addr, addrbuf,
				sizeof(addrbuf)),
		      strerror(errno));
}

static void
pex_send_hello(struct network *net, struct network_peer *peer)
{
	struct pex_hello *data;

	pex_msg_init(net, PEX_MSG_HELLO);
	data = pex_msg_append(sizeof(*data));
	if (peer->state.endpoint.sa.sa_family == AF_INET6)
	    data->flags |= htons(PEER_EP_F_IPV6);
	if (network_get_local_addr(&data->local_addr, &peer->state.endpoint))
		return;

	pex_msg_send(net, peer);
}

static int
pex_msg_add_peer_endpoint(struct network *net, struct network_peer *peer,
			  struct network_peer *receiver)
{
	struct pex_peer_endpoint *data;
	uint16_t flags = 0;
	const void *addr;
	int port;
	int len;

	addr = network_endpoint_addr(&peer->state.endpoint, &len);
	port = peer->state.endpoint.in.sin_port;
	if (len > 4)
		flags |= PEER_EP_F_IPV6;
	if (network_endpoint_addr_equal(&peer->state.endpoint,
					&receiver->state.endpoint)) {
		if (!peer->state.has_local_ep_addr) {
			D_PEER(net, peer, "can't send peer to %s, missing local address",
			       network_peer_name(receiver));
			return -1;
		}

		addr = &peer->state.local_ep_addr;
		port = htons(peer->port);
		flags |= PEER_EP_F_LOCAL;
	}

	data = pex_msg_append(sizeof(*data));
	if (!data)
		return -1;

	memcpy(data->peer_id, peer->key, sizeof(data->peer_id));
	memcpy(data->addr, addr, len);
	data->port = port;
	data->flags = htons(flags);
	D_PEER(net, peer, "send endpoint to %s", network_peer_name(receiver));

	return 0;
}

static void
network_pex_handle_endpoint_change(struct network *net, struct network_peer *peer)
{
	struct network_peer *cur;

	vlist_for_each_element(&net->peers, cur, node) {
		if (cur == peer || !cur->state.connected || cur->indirect)
			continue;

		pex_msg_init(net, PEX_MSG_NOTIFY_PEERS);
		if (pex_msg_add_peer_endpoint(net, peer, cur))
			continue;

		pex_msg_send(net, cur);
	}
}

static void
network_pex_host_send_endpoint_notify(struct network *net, struct network_pex_host *host)
{
	union {
		struct {
			struct ip ip;
			struct udphdr udp;
		} ipv4;
		struct {
			struct ip6_hdr ip;
			struct udphdr udp;
		} ipv6;
	} packet = {};
	struct udphdr *udp;
	union network_endpoint dest_ep;
	union network_addr local_addr = {};
	int len;

	pex_msg_init_ext(net, PEX_MSG_ENDPOINT_NOTIFY, true);

	memcpy(&dest_ep, &host->endpoint, sizeof(dest_ep));

	/* work around issue with local address lookup for local broadcast */
	if (host->endpoint.sa.sa_family == AF_INET) {
		uint8_t *data = (uint8_t *)&dest_ep.in.sin_addr;

		if (data[3] == 0xff)
			data[3] = 0xfe;
	}
	network_get_local_addr(&local_addr, &dest_ep);

	memset(&dest_ep, 0, sizeof(dest_ep));
	dest_ep.sa.sa_family = host->endpoint.sa.sa_family;
	if (host->endpoint.sa.sa_family == AF_INET) {
		packet.ipv4.ip = (struct ip){
			.ip_hl = 5,
			.ip_v = 4,
			.ip_ttl = 64,
			.ip_p = IPPROTO_UDP,
			.ip_src = local_addr.in,
			.ip_dst = host->endpoint.in.sin_addr,
		};
		dest_ep.in.sin_addr = host->endpoint.in.sin_addr;
		udp = &packet.ipv4.udp;
		len = sizeof(packet.ipv4);
	} else {
		packet.ipv6.ip = (struct ip6_hdr){
			.ip6_flow = htonl(6 << 28),
			.ip6_hops = 128,
			.ip6_nxt = IPPROTO_UDP,
			.ip6_src = local_addr.in6,
			.ip6_dst = host->endpoint.in6.sin6_addr,
		};
		dest_ep.in6.sin6_addr = host->endpoint.in6.sin6_addr;
		udp = &packet.ipv6.udp;
		len = sizeof(packet.ipv6);
	}

	udp->uh_sport = htons(net->net_config.local_host->peer.port);
	udp->uh_dport = host->endpoint.in6.sin6_port;

	if (__pex_msg_send(-1, &dest_ep, &packet, len) < 0)
		D_NET(net, "pex_msg_send_raw failed: %s", strerror(errno));
}


static void
network_pex_host_send_port_notify(struct network *net, struct network_pex_host *host)
{
	struct pex_endpoint_port_notify *data;

	if (!net->stun.port_ext)
		return;

	pex_msg_init_ext(net, PEX_MSG_ENDPOINT_PORT_NOTIFY, true);

	data = pex_msg_append(sizeof(*data));
	data->port = htons(net->stun.port_ext);

	__pex_msg_send(-1, &host->endpoint, NULL, 0);
}

static void
network_pex_host_request_update(struct network *net, struct network_pex_host *host)
{
	char addrstr[INET6_ADDRSTRLEN];
	uint64_t version = 0;

	host->last_ping = unet_gettime();

	if (net->net_data_len)
		version = net->net_data_version;

	D("request network data from host %s",
	  inet_ntop(host->endpoint.sa.sa_family,
		    (host->endpoint.sa.sa_family == AF_INET6 ?
		     (const void *)&host->endpoint.in6.sin6_addr :
		     (const void *)&host->endpoint.in.sin_addr),
		    addrstr, sizeof(addrstr)));

	if (!pex_msg_update_request_init(net->config.pubkey, net->config.key,
					 net->config.auth_key, &host->endpoint,
					 version, true))
		return;

	__pex_msg_send(-1, &host->endpoint, NULL, 0);

	if (!net->net_config.local_host)
		return;

	network_pex_host_send_port_notify(net, host);
	network_pex_host_send_endpoint_notify(net, host);
}

static void
network_pex_free_host(struct network *net, struct network_pex_host *host)
{
	struct network_pex *pex = &net->pex;

	pex->num_hosts--;
	list_del(&host->list);
	free(host);
}

static void
network_pex_request_update_cb(struct uloop_timeout *t)
{
	struct network *net = container_of(t, struct network, pex.request_update_timer);
	struct network_pex *pex = &net->pex;
	struct network_pex_host *host, *tmp;
	uint64_t now = unet_gettime();

	uloop_timeout_set(t, 500);

	if (list_empty(&pex->hosts))
		return;

	list_for_each_entry_safe(host, tmp, &pex->hosts, list) {
		if (host->timeout && host->timeout < now) {
			network_pex_free_host(net, host);
			continue;
		}

		if (host->last_ping + 10 >= now)
			continue;

		list_move_tail(&host->list, &pex->hosts);
		network_pex_host_request_update(net, host);
	}
}

void network_pex_init(struct network *net)
{
	struct network_pex *pex = &net->pex;

	memset(pex, 0, sizeof(*pex));
	pex->fd.fd = -1;
	INIT_LIST_HEAD(&pex->hosts);
	pex->request_update_timer.cb = network_pex_request_update_cb;
}

static void
network_pex_query_hosts(struct network *net)
{
	struct network_host *host;
	uint64_t now;
	int rv = rand();
	int hosts = 0;
	int i;

	pex_msg_init(net, PEX_MSG_QUERY);

	avl_for_each_element(&net->hosts, host, node) {
		struct network_peer *peer = &host->peer;
		void *id;

		if ((net->stun.port_ext && host == net->net_config.local_host) ||
		    peer->state.connected || peer->endpoint || host->gateway)
			continue;

		id = pex_msg_append(PEX_ID_LEN);
		if (!id)
			break;

		memcpy(id, peer->key, PEX_ID_LEN);
		hosts++;
	}

	if (!hosts)
		return;

	now = unet_gettime();
	rv %= net->hosts.count;
	for (i = 0; i < 2; i++) {
		avl_for_each_element(&net->hosts, host, node) {
			struct network_peer *peer = &host->peer;

			if (rv > 0) {
				rv--;
				continue;
			}

			if (host == net->net_config.local_host)
				continue;

			if (!peer->state.connected ||
			    peer->state.last_query_sent + 15 >= now)
				continue;

			D_PEER(net, peer, "send query for %d hosts", hosts);
			pex_msg_send(net, peer);
			peer->state.last_query_sent = now;
			return;
		}
	}

}

static void
network_pex_send_ping(struct network *net, struct network_peer *peer)
{
	if (peer->state.ping_wait > 0 || !peer->state.endpoint.sa.sa_family)
		return;

	pex_msg_init(net, PEX_MSG_PING);
	pex_msg_send(net, peer);
	peer->state.ping_wait = 1 + net->net_config.keepalive / 2;
}

static void
network_pex_send_update_request(struct network *net, struct network_peer *peer,
				struct sockaddr_in6 *addr)
{
	union network_endpoint ep = {};
	uint64_t version = 0;

	if (addr)
		memcpy(&ep.in6, addr, sizeof(ep.in6));
	else
		pex_get_peer_addr(&ep.in6, net, peer);

	if (net->net_data_len)
		version = net->net_data_version;

	if (!pex_msg_update_request_init(net->config.pubkey, net->config.key,
					 net->config.auth_key, &ep,
					 version, !!addr))
		return;

	pex_msg_send_ext(net, peer, addr);
}

void network_pex_event(struct network *net, struct network_peer *peer,
		       enum pex_event ev)
{
	if (!network_pex_active(&net->pex))
		return;

	switch (ev) {
	case PEX_EV_HANDSHAKE:
		peer->state.last_query_sent = 0;
		pex_send_hello(net, peer);
		if (net->config.type == NETWORK_TYPE_DYNAMIC)
			network_pex_send_update_request(net, peer, NULL);
		break;
	case PEX_EV_ENDPOINT_CHANGE:
		network_pex_handle_endpoint_change(net, peer);
		break;
	case PEX_EV_QUERY:
		network_pex_query_hosts(net);
		break;
	case PEX_EV_PING:
		network_pex_send_ping(net, peer);
		break;
	}
}

static void
network_pex_recv_hello(struct network *net, struct network_peer *peer,
		       const struct pex_hello *data, size_t len)
{
	char addrstr[INET6_ADDRSTRLEN];
	uint16_t flags;
	int af;

	if (len < sizeof(*data))
		return;

	if (peer->state.has_local_ep_addr &&
	    !memcmp(&peer->state.local_ep_addr, data->local_addr, sizeof(data->local_addr)))
		return;

	flags = ntohs(data->flags);
	af = (flags & PEER_EP_F_IPV6) ? AF_INET6 : AF_INET;
	D_PEER(net, peer, "set local endpoint address to %s",
	       inet_ntop(af, data->local_addr, addrstr, sizeof(addrstr)));
	peer->state.has_local_ep_addr = true;
	memcpy(&peer->state.local_ep_addr, data->local_addr, sizeof(data->local_addr));
}

static void
network_pex_recv_peers(struct network *net, struct network_peer *peer,
		       const struct pex_peer_endpoint *data, size_t len)
{
	struct network_peer *local = &net->net_config.local_host->peer;
	struct network_peer *cur;

	for (; len >= sizeof(*data); len -= sizeof(*data), data++) {
		union network_endpoint *ep;
		uint16_t flags;
		void *addr;
		int len;

		if (!memcmp(data->peer_id, &local->key, PEX_ID_LEN)) {
			network_stun_update_port(net, false, ntohs(data->port));
			continue;
		}

		cur = pex_msg_peer(net, data->peer_id, false);
		if (!cur || cur == peer)
			continue;

		D_PEER(net, peer, "received peer address for %s",
		       network_peer_name(cur));
		flags = ntohs(data->flags);
		ep = &cur->state.next_endpoint[ENDPOINT_TYPE_PEX];
		ep->sa.sa_family = (flags & PEER_EP_F_IPV6) ? AF_INET6 : AF_INET;
		addr = network_endpoint_addr(ep, &len);
		memcpy(addr, data->addr, len);
		ep->in.sin_port = data->port;
	}
}

static void
network_pex_recv_query(struct network *net, struct network_peer *peer,
		       const uint8_t *data, size_t len)
{
	struct network_peer *cur;
	int resp = 0;

	pex_msg_init(net, PEX_MSG_NOTIFY_PEERS);
	for (; len >= 8; data += 8, len -= 8) {
		struct network_host *host;

		cur = pex_msg_peer(net, data, false);
		if (!cur || !cur->state.connected)
			continue;

		host = container_of(peer, struct network_host, peer);
		if (host->gateway)
			continue;

		if (!pex_msg_add_peer_endpoint(net, cur, peer))
			resp++;
	}

	if (!resp)
		return;

	D_PEER(net, peer, "send query response with %d hosts", resp);
	pex_msg_send(net, peer);
}

static void
network_pex_recv_ping(struct network *net, struct network_peer *peer)
{
	time_t now = time(NULL);

	if (peer->state.last_request == now)
		return;

	peer->state.last_request = now;
	pex_msg_init(net, PEX_MSG_PONG);
	pex_msg_send(net, peer);
}

static void
network_pex_recv_update_request(struct network *net, struct network_peer *peer,
				const uint8_t *data, size_t len,
				struct sockaddr_in6 *addr)
{
	struct pex_update_request *req = (struct pex_update_request *)data;
	struct pex_endpoint_port_notify *port_data;
	struct pex_msg_update_send_ctx ctx = {};
	uint64_t req_version = be64_to_cpu(req->cur_version);
	int *query_count;
	bool done = false;

	if (len < sizeof(struct pex_update_request))
		return;

	if (net->config.type != NETWORK_TYPE_DYNAMIC)
		return;

	if (peer)
		query_count = &peer->state.num_net_queries;
	else
		query_count = &net->num_net_queries;

	if (++*query_count > 10)
		return;

	D("receive update request, local version=%"PRIu64", remote version=%"PRIu64, net->net_data_version, req_version);

	if (req_version >= net->net_data_version) {
		struct pex_update_response_no_data *res;

		pex_msg_init_ext(net, PEX_MSG_UPDATE_RESPONSE_NO_DATA, !!addr);
		res = pex_msg_append(sizeof(*res));
		res->req_id = req->req_id;
		res->cur_version = cpu_to_be64(net->net_data_version);
		pex_msg_send_ext(net, peer, addr);
	}

	if (req_version > net->net_data_version)
		network_pex_send_update_request(net, peer, addr);

	if (!peer || !net->net_data_len)
		return;

	if (req_version >= net->net_data_version)
		goto out;

	pex_msg_update_response_init(&ctx, net->config.pubkey, net->config.auth_key,
				     peer->key, !!addr, (void *)data,
				     net->net_data, net->net_data_len);
	while (!done) {
		pex_msg_send_ext(net, peer, addr);
		done = !pex_msg_update_response_continue(&ctx);
	}

out:
	if (peer->state.connected || !net->net_config.local_host)
		return;

	pex_msg_init_ext(net, PEX_MSG_ENDPOINT_PORT_NOTIFY, !!addr);

	port_data = pex_msg_append(sizeof(*port_data));
	if (net->stun.port_ext)
		port_data->port = htons(net->stun.port_ext);
	else
		port_data->port = htons(net->net_config.local_host->peer.port);

	pex_msg_send_ext(net, peer, addr);
}

static void
network_pex_recv_update_response(struct network *net, const uint8_t *data, size_t len,
			      struct sockaddr_in6 *addr, enum pex_opcode op)
{
	struct network_peer *peer;
	void *net_data;
	int net_data_len = 0;
	uint64_t version = 0;
	bool no_prev_data = !net->net_data_len;

	if (net->config.type != NETWORK_TYPE_DYNAMIC)
		return;

	net_data = pex_msg_update_response_recv(data, len, op, &net_data_len, &version);
	if (!net_data)
		return;

	if (version <= net->net_data_version) {
		free(net_data);
		return;
	}

	D_NET(net, "received updated network data, len=%d", net_data_len);
	free(net->net_data);

	net->net_data = net_data;
	net->net_data_len = net_data_len;
	net->net_data_version = version;
	if (network_save_dynamic(net) < 0)
		return;

	uloop_timeout_set(&net->reload_timer, no_prev_data ? 1 : UNETD_DATA_UPDATE_DELAY);
	vlist_for_each_element(&net->peers, peer, node) {
		if (!peer->state.connected || !peer->pex_port)
			continue;
		network_pex_send_update_request(net, peer, NULL);
	}
}

static void
network_pex_recv(struct network *net, struct network_peer *peer, struct pex_hdr *hdr)
{
	const void *data = hdr + 1;

	if (hdr->version != 0)
		return;

	D_PEER(net, peer, "PEX rx op=%d", hdr->opcode);
	switch (hdr->opcode) {
	case PEX_MSG_HELLO:
		network_pex_recv_hello(net, peer, data, hdr->len);
		break;
	case PEX_MSG_NOTIFY_PEERS:
		network_pex_recv_peers(net, peer, data, hdr->len);
		break;
	case PEX_MSG_QUERY:
		network_pex_recv_query(net, peer, data, hdr->len);
		break;
	case PEX_MSG_PING:
		network_pex_recv_ping(net, peer);
		break;
	case PEX_MSG_PONG:
		break;
	case PEX_MSG_UPDATE_REQUEST:
		network_pex_recv_update_request(net, peer, data, hdr->len,
						NULL);
		break;
	case PEX_MSG_UPDATE_RESPONSE:
	case PEX_MSG_UPDATE_RESPONSE_DATA:
	case PEX_MSG_UPDATE_RESPONSE_NO_DATA:
		network_pex_recv_update_response(net, data, hdr->len,
					      NULL, hdr->opcode);
		break;
	case PEX_MSG_ENDPOINT_NOTIFY:
		break;
	}
}

static void
network_pex_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct network *net = container_of(fd, struct network, pex.fd);
	struct network_peer *local = &net->net_config.local_host->peer;
	struct network_peer *peer;
	struct sockaddr_in6 sin6;
	static char buf[PEX_BUF_SIZE];
	struct pex_hdr *hdr = (struct pex_hdr *)buf;
	ssize_t len;

	while (1) {
		socklen_t slen = sizeof(sin6);

		len = recvfrom(fd->fd, buf, sizeof(buf), 0, (struct sockaddr *)&sin6, &slen);
		if (len < 0) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN)
				break;

			D_NET(net, "recvfrom failed: %s", strerror(errno));
			network_pex_close(net);
			return;
		}

		if (!len)
			continue;

		hdr = pex_rx_accept(buf, len, false);
		if (!hdr)
			continue;

		peer = pex_msg_peer(net, hdr->id, false);
		if (!peer)
			continue;

		if (memcmp(&sin6.sin6_addr, &peer->local_addr.in6, sizeof(sin6.sin6_addr)) != 0)
			continue;

		if (peer == local)
			continue;

		network_pex_recv(net, peer, hdr);
	}
}

struct network_pex_host *
network_pex_create_host(struct network *net, union network_endpoint *ep,
			unsigned int timeout)
{
	struct network_pex *pex = &net->pex;
	struct network_pex_host *host;
	uint64_t now = unet_gettime();
	bool new_host = false;

	list_for_each_entry(host, &pex->hosts, list) {
		if (memcmp(&host->endpoint, ep, sizeof(host->endpoint)) != 0)
			continue;

		if (host->last_ping + 10 < now) {
			list_move_tail(&host->list, &pex->hosts);
			network_pex_host_request_update(net, host);
		}
		goto out;
	}

	host = calloc(1, sizeof(*host));
	new_host = true;
	memcpy(&host->endpoint, ep, sizeof(host->endpoint));
	list_add_tail(&host->list, &pex->hosts);
	pex->num_hosts++;

out:
	if (timeout && (new_host || host->timeout))
		host->timeout = timeout + unet_gettime();
	return host;
}

static void
network_pex_open_auth_connect(struct network *net)
{
	struct network_pex *pex = &net->pex;
	struct network_peer *peer;
	struct blob_attr *cur;
	int rem;

	if (net->config.type != NETWORK_TYPE_DYNAMIC)
		return;

	uloop_timeout_set(&pex->request_update_timer, 5000);

	vlist_for_each_element(&net->peers, peer, node) {
		union network_endpoint ep = {};

		if (!peer->endpoint || peer->dynamic)
			continue;

		if (network_get_endpoint(&ep, AF_UNSPEC, peer->endpoint,
					 UNETD_GLOBAL_PEX_PORT, 0) < 0)
			continue;

		ep.in.sin_port = htons(UNETD_GLOBAL_PEX_PORT);
		network_pex_create_host(net, &ep, 0);
	}

	if (!net->config.auth_connect)
		return;

	blobmsg_for_each_attr(cur, net->config.auth_connect, rem) {
		union network_endpoint ep = {};

		if (network_get_endpoint(&ep, AF_UNSPEC, blobmsg_get_string(cur),
					 UNETD_GLOBAL_PEX_PORT, 0) < 0)
			continue;

		network_pex_create_host(net, &ep, 0);
	}
}


static void
__network_pex_reload_iface(struct network *net, struct blob_attr *data)
{
	static const struct blobmsg_policy policy[] = {
		{ "address", BLOBMSG_TYPE_STRING },
		{ "mask", BLOBMSG_TYPE_INT32 },
	};
	struct network_pex_host *host;
	struct blob_attr *tb[2], *cur;
	size_t rem;

	if (!data)
		return;

	blobmsg_for_each_attr(cur, data, rem) {
		union network_endpoint ep = {};
		uint32_t mask;

		blobmsg_parse_attr(policy, ARRAY_SIZE(policy), tb, cur);
		if (!tb[0] || !tb[1])
			continue;

		mask = blobmsg_get_u32(tb[1]);
		if (mask >= 31 || !mask)
			continue;

		if (network_get_endpoint(&ep, AF_INET, blobmsg_get_string(tb[0]),
					 UNETD_GLOBAL_PEX_PORT, 0) < 0)
			continue;

		*(uint32_t *)&ep.in.sin_addr |= htonl((~0U) >> mask);
		host = network_pex_create_host(net, &ep, 0);
		host->interface = true;
	}
}

static void
__network_pex_reload(struct network *net)
{
	struct network_pex *pex = &net->pex;
	struct network_pex_host *host, *tmp;
	struct blob_attr *cur;
	size_t rem;

	if (!net->config.local_network)
		return;

	list_for_each_entry_safe(host, tmp, &pex->hosts, list)
		if (host->interface)
			network_pex_free_host(net, host);

	blobmsg_for_each_attr(cur, net->config.local_network, rem) {
		const char *name = blobmsg_get_string(cur);
		struct blob_attr *addrs;

		addrs = unetd_ubus_get_network_addr_list(name);
		__network_pex_reload_iface(net, addrs);
	}
}

static void
network_pex_reload_cb(struct uloop_timeout *t)
{
	struct network *net;

	avl_for_each_element(&networks, net, node)
		__network_pex_reload(net);
}

void network_pex_reload(void)
{
	static struct uloop_timeout timer = {
		.cb = network_pex_reload_cb,
	};

	uloop_timeout_set(&timer, 1);
}

int network_pex_open(struct network *net)
{
	struct network_host *local_host = net->net_config.local_host;
	struct network_peer *local;
	struct network_pex *pex = &net->pex;
	struct sockaddr_in6 sin6 = {};
	int yes = 1;
	int fd;

	network_pex_open_auth_connect(net);
	__network_pex_reload(net);

	if (!local_host || !local_host->peer.pex_port)
		return 0;

	local = &local_host->peer;
	fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -1;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, &local->local_addr.in6,
	       sizeof(local->local_addr.in6));
	sin6.sin6_port = htons(local_host->peer.pex_port);

	if (bind(fd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0) {
		perror("bind");
		goto close;
	}

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#ifdef linux
	setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
		   network_name(net), strlen(network_name(net)));
#endif

	pex->fd.fd = fd;
	pex->fd.cb = network_pex_fd_cb;
	uloop_fd_add(&pex->fd, ULOOP_READ);

	return 0;

close:
	close(fd);
	return -1;
}

void network_pex_close(struct network *net)
{
	struct network_pex *pex = &net->pex;
	struct network_pex_host *host, *tmp;
	uint64_t now = unet_gettime();

	uloop_timeout_cancel(&pex->request_update_timer);
	list_for_each_entry_safe(host, tmp, &pex->hosts, list) {
		if (host->timeout)
			continue;

		if (host->last_active + UNETD_PEX_HOST_ACITVE_TIMEOUT >= now)
			continue;

		network_pex_free_host(net, host);
	}

	if (pex->fd.fd < 0)
		return;

	uloop_fd_delete(&pex->fd);
	close(pex->fd.fd);
	network_pex_init(net);
}

void network_pex_free(struct network *net)
{
	struct network_pex *pex = &net->pex;
	struct network_pex_host *host, *tmp;

	list_for_each_entry_safe(host, tmp, &pex->hosts, list)
		network_pex_free_host(net, host);
}

static struct network *
global_pex_find_network(const uint8_t *id)
{
	struct network *net;

	avl_for_each_element(&networks, net, node) {
		if (!memcmp(id, net->config.auth_key, PEX_ID_LEN))
			return net;
	}

	return NULL;
}

static void
global_pex_set_active(struct network *net, struct sockaddr_in6 *addr)
{
	struct network_pex *pex = &net->pex;
	struct network_pex_host *host;

	list_for_each_entry(host, &pex->hosts, list) {
		if (memcmp(&host->endpoint.in6, addr, sizeof(*addr)) != 0)
			continue;

		host->last_active = unet_gettime();
	}
}

static void
global_pex_recv(void *msg, size_t msg_len, struct sockaddr_in6 *addr)
{
	struct pex_hdr *hdr;
	struct pex_ext_hdr *ehdr;
	struct network_peer *peer;
	struct network *net = NULL;
	char buf[INET6_ADDRSTRLEN];
	void *data;
	int addr_len;
	int ep_idx = ENDPOINT_TYPE_ENDPOINT_NOTIFY;

	if (stun_msg_is_valid(msg, msg_len)) {
		avl_for_each_element(&networks, net, node)
			network_stun_rx_packet(net, msg, msg_len);
	}

	hdr = pex_rx_accept(msg, msg_len, true);
	if (!hdr)
		return;

	ehdr = (void *)(hdr + 1);
	data = (void *)(ehdr + 1);

	if (hdr->version != 0)
		return;

	if (hdr->opcode != PEX_MSG_ENROLL) {
		net = global_pex_find_network(ehdr->auth_id);
		if (!net || net->config.type != NETWORK_TYPE_DYNAMIC)
			return;

		*(uint64_t *)hdr->id ^= pex_network_hash(net->config.auth_key, ehdr->nonce);

		global_pex_set_active(net, addr);
	}

	D("PEX global rx op=%d", hdr->opcode);
	switch (hdr->opcode) {
	case PEX_MSG_HELLO:
	case PEX_MSG_NOTIFY_PEERS:
	case PEX_MSG_QUERY:
	case PEX_MSG_PING:
	case PEX_MSG_PONG:
		break;
	case PEX_MSG_UPDATE_REQUEST:
		peer = pex_msg_peer(net, hdr->id, true);
		network_pex_recv_update_request(net, peer, data, hdr->len,
						addr);
		break;
	case PEX_MSG_UPDATE_RESPONSE:
	case PEX_MSG_UPDATE_RESPONSE_DATA:
	case PEX_MSG_UPDATE_RESPONSE_NO_DATA:
		network_pex_recv_update_response(net, data, hdr->len, addr, hdr->opcode);
		break;
	case PEX_MSG_ENDPOINT_PORT_NOTIFY:
		if (hdr->len < sizeof(struct pex_endpoint_port_notify))
			break;

		ep_idx = ENDPOINT_TYPE_ENDPOINT_PORT_NOTIFY;
		fallthrough;
	case PEX_MSG_ENDPOINT_NOTIFY:
		peer = pex_msg_peer(net, hdr->id, true);
		if (!peer)
			break;

		D_PEER(net, peer, "receive endpoint notification from %s",
		  inet_ntop(addr->sin6_family, network_endpoint_addr((void *)addr, &addr_len),
			    buf, sizeof(buf)));

		memcpy(&peer->state.next_endpoint[ep_idx], addr, sizeof(*addr));
		if (hdr->opcode == PEX_MSG_ENDPOINT_PORT_NOTIFY) {
			struct pex_endpoint_port_notify *port = data;
			union network_endpoint host_ep = {
				.in6 = *addr
			};

			peer->state.next_endpoint[ep_idx].in.sin_port = port->port;
			if (net->pex.num_hosts < NETWORK_PEX_HOSTS_LIMIT)
				network_pex_create_host(net, &host_ep, 120);
		}
		break;
	case PEX_MSG_ENROLL:
		pex_enroll_recv(data, hdr->len, addr);
		break;
	}
}

static void
pex_recv_control(struct pex_msg_local_control *msg, int len)
{
	struct network *net;

	if (msg->msg_type != 0)
		return;

	net = global_pex_find_network(msg->auth_id);
	if (!net)
		return;

	if (!msg->timeout)
		msg->timeout = 60;
	network_pex_create_host(net, &msg->ep, msg->timeout);
}

int global_pex_open(const char *unix_path)
{
	struct sockaddr_in6 sin6 = {};
	int ret;

	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(global_pex_port);

	ret = pex_open(&sin6, sizeof(sin6), global_pex_recv, true);

	if (unix_path)
		pex_unix_open(unix_path, pex_recv_control);

	return ret;
}
