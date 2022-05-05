#include "unetd.h"

static const struct wg_ops *wg_get_ops(struct network *net)
{
	if (dummy_mode)
		return &wg_dummy_ops;

	if (wg_user_ops.check(net))
		return &wg_user_ops;

#ifdef linux
	return &wg_linux_ops;
#else
	return NULL;
#endif
}

int wg_init_network(struct network *net)
{
	net->wg.ops = wg_get_ops(net);

	if (!net->wg.ops)
		return -1;

	return net->wg.ops->init(net);
}

void wg_cleanup_network(struct network *net)
{
	if (net->wg.ops)
		net->wg.ops->cleanup(net);
}

struct network_peer *wg_peer_update_start(struct network *net, const uint8_t *key)
{
	struct network_peer *peer;

	peer = vlist_find(&net->peers, key, peer, node);
	if (!peer)
		return NULL;

	peer->state.handshake = false;
	peer->state.idle++;
	if (peer->state.idle >= 2 * net->net_config.keepalive)
		peer->state.connected = false;
	if (peer->state.idle > net->net_config.keepalive)
		network_pex_event(net, peer, PEX_EV_PING);

	return peer;
}

void wg_peer_update_done(struct network *net, struct network_peer *peer)
{
	if (peer->state.handshake)
		network_pex_event(net, peer, PEX_EV_HANDSHAKE);
}

void wg_peer_set_last_handshake(struct network *net, struct network_peer *peer,
				uint64_t now, uint64_t sec)
{
	if (sec == peer->state.last_handshake)
		return;

	peer->state.handshake = true;
	peer->state.last_handshake = sec;
	sec = now - sec;
	if (sec <= net->net_config.keepalive) {
		peer->state.connected = true;
		if (peer->state.idle > sec)
			peer->state.idle = sec;
	}
}

void wg_peer_set_rx_bytes(struct network *net, struct network_peer *peer,
			  uint64_t bytes)
{
	int64_t diff = bytes - peer->state.rx_bytes;

	peer->state.rx_bytes = bytes;
	if (diff > 0) {
		peer->state.idle = 0;
		peer->state.connected = true;
	}
}

void wg_peer_set_endpoint(struct network *net, struct network_peer *peer,
			  void *data, size_t len)
{
	if (len > sizeof(peer->state.endpoint))
		return;

	if (!memcmp(&peer->state.endpoint, data, len))
		return;

	memset(&peer->state.endpoint, 0, sizeof(peer->state.endpoint));
	memcpy(&peer->state.endpoint, data, len);
	network_pex_event(net, peer, PEX_EV_ENDPOINT_CHANGE);
}
