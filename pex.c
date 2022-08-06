// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include "unetd.h"

#define PEX_BUF_SIZE	1024

enum pex_opcode {
	PEX_MSG_HELLO,
	PEX_MSG_NOTIFY_PEERS,
	PEX_MSG_QUERY,
	PEX_MSG_PING,
	PEX_MSG_PONG,
};

#define PEX_ID_LEN		8

struct pex_hdr {
	uint8_t version;
	uint8_t opcode;
	uint16_t len;
	uint8_t id[PEX_ID_LEN];
};

#define PEER_EP_F_IPV6		(1 << 0)
#define PEER_EP_F_LOCAL		(1 << 1)

struct pex_peer_endpoint {
	uint16_t flags;
	uint16_t port;
	uint8_t peer_id[PEX_ID_LEN];
	uint8_t addr[16];
};

struct pex_hello {
	uint16_t flags;
	uint8_t local_addr[16];
};

static char tx_buf[PEX_BUF_SIZE];

static const char *pex_peer_id_str(const uint8_t *key)
{
	static char str[20];
	int i;

	for (i = 0; i < 8; i++)
		sprintf(str + i * 2, "%02x", key[i]);

	return str;
}


static struct network_peer *
pex_msg_peer(struct network *net, const uint8_t *id)
{
	struct network_peer *peer;
	uint8_t key[WG_KEY_LEN] = {};

	memcpy(key, id, PEX_ID_LEN);
	peer = avl_find_ge_element(&net->peers.avl, key, peer, node.avl);
	if (!peer || memcmp(peer->key, key, PEX_ID_LEN) != 0) {
		D_NET(net, "can't find peer %s", pex_peer_id_str(id));
		return NULL;
	}

	return peer;
}

static struct pex_hdr *pex_msg_init(struct network *net, uint8_t opcode)
{
	struct pex_hdr *hdr = (struct pex_hdr *)tx_buf;

	hdr->version = 0;
	hdr->opcode = opcode;
	hdr->len = 0;
	memcpy(hdr->id, net->config.pubkey, sizeof(hdr->id));

	return hdr;
}

static void *pex_msg_append(size_t len)
{
	struct pex_hdr *hdr = (struct pex_hdr *)tx_buf;
	int ofs = hdr->len + sizeof(struct pex_hdr);
	void *buf = &tx_buf[ofs];

	if (sizeof(tx_buf) - ofs < len)
		return NULL;

	hdr->len += len;
	memset(buf, 0, len);

	return buf;
}

static void pex_msg_send(struct network *net, struct network_peer *peer)
{
	struct sockaddr_in6 sin6 = {};
	struct pex_hdr *hdr = (struct pex_hdr *)tx_buf;
	size_t tx_len = sizeof(*hdr) + hdr->len;
	int ret;

	if (peer == &net->net_config.local_host->peer || !peer->state.connected)
		return;

	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, &peer->local_addr.in6,
	       sizeof(peer->local_addr.in6));
	sin6.sin6_port = htons(net->net_config.pex_port);
	hdr->len = htons(hdr->len);
	ret = sendto(net->pex.fd.fd, tx_buf, tx_len, 0, (struct sockaddr *)&sin6, sizeof(sin6));
	hdr->len = ntohs(hdr->len);
	if (ret < 0)
		D_PEER(net, peer, "pex_msg_send failed: %s", strerror(errno));
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
		if (cur == peer || !cur->state.connected)
			continue;

		pex_msg_init(net, PEX_MSG_NOTIFY_PEERS);
		if (pex_msg_add_peer_endpoint(net, peer, cur))
			continue;

		pex_msg_send(net, cur);
	}
}

void network_pex_init(struct network *net)
{
	struct network_pex *pex = &net->pex;

	memset(pex, 0, sizeof(*pex));
	pex->fd.fd = -1;
}

static void
network_pex_query_hosts(struct network *net)
{
	struct network_host *host;
	int rv = rand();
	int hosts = 0;
	int i;

	pex_msg_init(net, PEX_MSG_QUERY);

	avl_for_each_element(&net->hosts, host, node) {
		struct network_peer *peer = &host->peer;
		void *id;

		if (host == net->net_config.local_host ||
		    peer->state.connected ||
		    peer->endpoint)
			continue;

		id = pex_msg_append(PEX_ID_LEN);
		if (!id)
			break;

		memcpy(id, peer->key, PEX_ID_LEN);
		hosts++;
	}

	if (!hosts)
		return;

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

			if (!peer->state.connected)
				continue;

			D_PEER(net, peer, "send query for %d hosts", hosts);
			pex_msg_send(net, peer);
			return;
		}
	}

}

static void
network_pex_send_ping(struct network *net, struct network_peer *peer)
{
	pex_msg_init(net, PEX_MSG_PING);
	pex_msg_send(net, peer);
}

void network_pex_event(struct network *net, struct network_peer *peer,
		       enum pex_event ev)
{
	if (!network_pex_active(&net->pex))
		return;

	if (peer)
		D_PEER(net, peer, "PEX event type=%d", ev);
	else
		D_NET(net, "PEX event type=%d", ev);

	switch (ev) {
	case PEX_EV_HANDSHAKE:
		pex_send_hello(net, peer);
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

		cur = pex_msg_peer(net, data->peer_id);
		if (!cur)
			continue;

		if (cur == peer || cur == local)
			continue;

		D_PEER(net, peer, "received peer address for %s\n",
		       network_peer_name(cur));
		flags = ntohs(data->flags);
		ep = &cur->state.next_endpoint;
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
		cur = pex_msg_peer(net, data);
		if (!cur || !cur->state.connected)
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

		if (len < sizeof(*hdr))
			continue;

		hdr->len = ntohs(hdr->len);
		if (len - sizeof(hdr) < hdr->len)
			continue;

		peer = pex_msg_peer(net, hdr->id);
		if (!peer)
			continue;

		if (memcmp(&sin6.sin6_addr, &peer->local_addr.in6, sizeof(sin6.sin6_addr)) != 0)
			continue;

		if (peer == local)
			continue;

		network_pex_recv(net, peer, hdr);
	}
}

int network_pex_open(struct network *net)
{
	struct network_peer *local = &net->net_config.local_host->peer;
	struct network_pex *pex = &net->pex;
	struct sockaddr_in6 sin6 = {};
	int yes = 1;
	int fd;

	if (!local || !net->net_config.pex_port)
		return 0;

	fd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -1;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	sin6.sin6_family = AF_INET6;
	memcpy(&sin6.sin6_addr, &local->local_addr.in6,
	       sizeof(local->local_addr.in6));
	sin6.sin6_port = htons(net->net_config.pex_port);

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

	if (pex->fd.fd < 0)
		return;

	uloop_fd_delete(&pex->fd);
	close(pex->fd.fd);
	network_pex_init(net);
}
