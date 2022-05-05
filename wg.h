// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_WG_H
#define __UNETD_WG_H

#define WG_KEY_LEN	32
#define WG_KEY_LEN_HEX	(WG_KEY_LEN * 2 + 1)

enum wg_update_cmd {
	WG_PEER_CREATE,
	WG_PEER_UPDATE,
	WG_PEER_DELETE,
};

struct network;
struct network_peer;
union network_endpoint;

struct wg_ops {
	const char *name;

	bool (*check)(struct network *net);

	int (*init)(struct network *net);
	void (*cleanup)(struct network *net);
	int (*init_local)(struct network *net, struct network_peer *peer);
	int (*peer_refresh)(struct network *net);
	int (*peer_update)(struct network *net, struct network_peer *peer,
			   enum wg_update_cmd cmd);
	int (*peer_connect)(struct network *net, struct network_peer *peer,
			    union network_endpoint *ep);
};

struct wg {
	const struct wg_ops *ops;
};

extern const struct wg_ops wg_dummy_ops;
extern const struct wg_ops wg_user_ops;
extern const struct wg_ops wg_linux_ops;

int wg_init_network(struct network *net);
void wg_cleanup_network(struct network *net);

#define wg_init_local(net, ...)		(net)->wg.ops->init_local(net, ##__VA_ARGS__)
#define wg_peer_update(net, ...)	(net)->wg.ops->peer_update(net, ##__VA_ARGS__)
#define wg_peer_connect(net, ...)	(net)->wg.ops->peer_connect(net, ##__VA_ARGS__)
#define wg_peer_refresh(net)		(net)->wg.ops->peer_refresh(net)

/* internal */
struct network_peer *wg_peer_update_start(struct network *net, const uint8_t *key);
void wg_peer_update_done(struct network *net, struct network_peer *peer);
void wg_peer_set_last_handshake(struct network *net, struct network_peer *peer,
				uint64_t now, uint64_t sec);
void wg_peer_set_rx_bytes(struct network *net, struct network_peer *peer,
			  uint64_t bytes);
void wg_peer_set_endpoint(struct network *net, struct network_peer *peer,
			  void *data, size_t len);

#endif
