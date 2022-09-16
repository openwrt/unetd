#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string.h>
#include <errno.h>

#include <libubox/usock.h>

#include "unetd.h"

static inline int avl_stun_cmp(const void *k1, const void *k2, void *priv)
{
	return memcmp(k1, k2, 12);
}

static bool has_connected_peer(struct network *net, bool pex)
{
	struct network_peer *peer;

	vlist_for_each_element(&net->peers, peer, node) {
		if (pex && !peer->pex_port)
			continue;

		if (peer->state.connected)
			return true;
	}

	return false;
}

void network_stun_server_add(struct network *net, const char *host)
{
	struct network_stun *stun = &net->stun;
	struct network_stun_server *s;
	char *name_buf;

	s = calloc_a(sizeof(*s), &name_buf, strlen(host) + 1);
	s->pending_node.key = s->req.transaction;
	s->host = strcpy(name_buf, host);

	list_add_tail(&s->list, &stun->servers);
}

static void
network_stun_close_socket(struct network *net)
{
	struct network_host *local = net->net_config.local_host;
	struct network_stun *stun = &net->stun;

	if (!stun->wgport_disabled)
		return;

	D_NET(net, "close STUN socket");
	uloop_fd_delete(&stun->socket);
	close(stun->socket.fd);
	wg_init_local(net, &local->peer);
	stun->wgport_disabled = false;
}

static void
network_stun_socket_cb(struct uloop_fd *fd, unsigned int events)
{
	struct network_stun *stun = container_of(fd, struct network_stun, socket);
	struct network *net = container_of(stun, struct network, stun);
	char buf[1024];
	ssize_t len;

	while (1) {
		len = recv(fd->fd, buf, sizeof(buf), 0);
		if (len < 0) {
			if (errno == EAGAIN)
				break;
			if (errno == EINTR)
				continue;

			perror("recv");
			network_stun_close_socket(net);
			return;
		}

		if (!stun_msg_is_valid(buf, len))
			continue;

		network_stun_rx_packet(net, buf, len);
	}
}

static void
network_stun_open_socket(struct network *net)
{
	struct network_host *local = net->net_config.local_host;
	struct network_stun *stun = &net->stun;
	int fd;

	if (stun->wgport_disabled)
		return;

	D_NET(net, "open STUN socket");
	wg_init_local(net, NULL);

	fd = usock(USOCK_SERVER | USOCK_UDP | USOCK_IPV4ONLY | USOCK_NONBLOCK,
		   NULL, usock_port(stun->port_local));
	if (fd < 0) {
		wg_init_local(net, &local->peer);
		return;
	}

	stun->socket.fd = fd;
	uloop_fd_add(&stun->socket, ULOOP_READ);
	stun->wgport_disabled = true;
}

static bool
network_stun_query_next(struct network *net)
{
	struct network_stun *stun = &net->stun;
	struct network_stun_server *s;
	char addrstr[INET6_ADDRSTRLEN];
	union network_endpoint ep;
	uint16_t res_port = 0;
	const void *msg;
	ssize_t ret;
	size_t len;

	s = list_first_entry(&stun->servers, struct network_stun_server, list);
	if (s->pending)
		return false;

	/* send next query */
	if (network_get_endpoint(&ep, AF_INET, s->host, 0, s->seq++) < 0) {
		D_NET(net, "lookup failed for STUN host %s", s->host);
		goto out;
	}

	if (ep.sa.sa_family != AF_INET || !ep.in.sin_port)
		goto out;

	if (!stun->wgport_disabled && stun->auth_port_ext)
		res_port = stun->auth_port_ext;

	D_NET(net, "Send STUN query to %s, res_port=%d, wg_disabled=%d",
	      inet_ntop(ep.sa.sa_family, network_endpoint_addr(&ep, NULL),
			addrstr, sizeof(addrstr)), res_port, stun->wgport_disabled);
	msg = stun_msg_request_prepare(&s->req, &len, res_port);
	if (!msg)
		goto out;

retry:
	s->req_auth_port = false;
	if (stun->wgport_disabled) {
		ret = sendto(stun->socket.fd, msg, len, 0, &ep.sa, sizeof(ep.in));
	} else if (!stun->auth_port_ext) {
		s->req_auth_port = true;
		ret = sendto(pex_socket(), msg, len, 0, &ep.sa, sizeof(ep.in));
	} else {
		struct {
		    struct ip ip;
		    struct udphdr udp;
		} packet_hdr = {};
		union network_addr local_addr = {};

		network_get_local_addr(&local_addr, &ep);
		packet_hdr.ip = (struct ip){
			.ip_hl = 5,
			.ip_v = 4,
			.ip_ttl = 64,
			.ip_p = IPPROTO_UDP,
			.ip_src = local_addr.in,
			.ip_dst = ep.in.sin_addr,
		};
		packet_hdr.udp = (struct udphdr){
			.uh_sport = htons(stun->port_local),
			.uh_dport = ep.in.sin_port,
		};
		ep.in.sin_port = 0;

		ret = sendto_rawudp(pex_raw_socket(AF_INET), &ep,
				    &packet_hdr, sizeof(packet_hdr),
				    msg, len);
	}

	if (ret < 0 && errno == EINTR)
		goto retry;

out:
	avl_insert(&stun->pending, &s->pending_node);
	s->pending = true;

	if (!list_is_last(&s->list, &stun->servers))
		list_move_tail(&s->list, &stun->servers);

	return true;
}

static void
network_stun_query_clear_pending(struct network *net)
{
	struct network_stun *stun = &net->stun;
	struct network_stun_server *s;

	list_for_each_entry(s, &stun->servers, list) {
		if (!s->pending)
			continue;

		avl_delete(&stun->pending, &s->pending_node);
		s->pending = false;
	}
}

void network_stun_rx_packet(struct network *net, const void *data, size_t len)
{
	struct network_stun *stun = &net->stun;
	const struct stun_msg_hdr *hdr = data;
	struct network_stun_server *s;

	s = avl_find_element(&stun->pending, hdr->transaction, s, pending_node);
	if (!s)
		return;

	if (!stun_msg_request_complete(&s->req, data, len))
		return;

	if (!s->req.port)
		return;

	network_stun_update_port(net, s->req_auth_port, s->req.port);
	if (s->req_auth_port)
		stun->state = STUN_STATE_STUN_QUERY_SEND;
	else
		stun->state = STUN_STATE_IDLE;

	network_stun_query_clear_pending(net);

	uloop_timeout_set(&stun->timer, 1);
}

static void
network_stun_timer_cb(struct uloop_timeout *t)
{
	struct network_stun *stun = container_of(t, struct network_stun, timer);
	struct network *net = container_of(stun, struct network, stun);
	unsigned int next = 0;

restart:
	switch (stun->state) {
	case STUN_STATE_IDLE:
		network_stun_close_socket(net);
		next = 15 * 60 * 1000;
		stun->state = STUN_STATE_STUN_QUERY_SEND;
		D_NET(net, "STUN idle");
		break;
	case STUN_STATE_PEX_QUERY_WAIT:
		stun->state = STUN_STATE_STUN_QUERY_SEND;
		fallthrough;
	case STUN_STATE_STUN_QUERY_SEND:
		if (network_stun_query_next(net)) {
			next = 50;
			break;
		}

		stun->state = STUN_STATE_STUN_QUERY_WAIT;
		D_NET(net, "wait for STUN server responses");
		next = 1000;
		break;
	case STUN_STATE_STUN_QUERY_WAIT:
		D_NET(net, "timeout waiting for STUN server responses, retry=%d", stun->retry);
		network_stun_query_clear_pending(net);
		if (stun->retry > 0) {
			stun->retry--;
			stun->state = STUN_STATE_STUN_QUERY_SEND;
			goto restart;
		}

		if (!stun->port_ext && !stun->wgport_disabled) {
			network_stun_open_socket(net);
			stun->state = STUN_STATE_STUN_QUERY_SEND;
			stun->retry = 2;
		} else {
			stun->state = STUN_STATE_IDLE;
		}
		goto restart;
	}

	if (next)
		uloop_timeout_set(t, next);
}

void network_stun_update_port(struct network *net, bool auth, uint16_t val)
{
	struct network_stun *stun = &net->stun;
	uint16_t *port = auth ? &stun->auth_port_ext : &stun->port_ext;

	D_NET(net, "Update external %s port: %d", auth ? "auth" : "data", val);
	*port = val;
}

void network_stun_start(struct network *net)
{
	struct network_host *local = net->net_config.local_host;
	struct network_stun *stun = &net->stun;
	unsigned int next = 1;

	if (!local || list_empty(&stun->servers))
		return;

	if (local->peer.port != stun->port_local) {
		stun->port_ext = 0;
		stun->port_local = local->peer.port;
	}

	if (!stun->port_ext && has_connected_peer(net, true)) {
		D_NET(net, "wait for port information from PEX");
		stun->state = STUN_STATE_PEX_QUERY_WAIT;
		next = 60 * 1000;
	} else {
		if (!stun->port_ext && !has_connected_peer(net, false))
			network_stun_open_socket(net);

		stun->state = STUN_STATE_STUN_QUERY_SEND;
		stun->retry = 2;
	}

	uloop_timeout_set(&stun->timer, next);
}

void network_stun_init(struct network *net)
{
	struct network_stun *stun = &net->stun;

	stun->socket.cb = network_stun_socket_cb;
	stun->timer.cb = network_stun_timer_cb;
	INIT_LIST_HEAD(&stun->servers);
	avl_init(&stun->pending, avl_stun_cmp, true, NULL);
}

void network_stun_free(struct network *net)
{
	struct network_stun *stun = &net->stun;
	struct network_stun_server *s, *tmp;

	uloop_timeout_cancel(&stun->timer);
	network_stun_close_socket(net);

	avl_remove_all_elements(&stun->pending, s, pending_node, tmp)
		s->pending = false;

	list_for_each_entry_safe(s, tmp, &stun->servers, list) {
		list_del(&s->list);
		free(s);
	}
}
