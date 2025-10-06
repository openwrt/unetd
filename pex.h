// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_PEX_H
#define __UNETD_PEX_H

#include <sys/socket.h>
#include <libubox/uloop.h>
#include "stun.h"
#include "utils.h"

#define NETWORK_PEX_HOSTS_LIMIT	128

struct network;
struct network_peer;

struct network_pex_host {
	struct list_head list;
	uint64_t timeout;
	uint64_t last_active;
	uint64_t last_ping;
	bool interface;
	union network_endpoint endpoint;
};

struct network_pex {
	struct uloop_fd fd;
	struct list_head hosts;
	int num_hosts;
	struct uloop_timeout request_update_timer;
	struct uloop_timeout request_psk_kex_status_timer;
};

enum network_stun_state {
	STUN_STATE_IDLE,
	STUN_STATE_PEX_QUERY_WAIT,
	STUN_STATE_STUN_QUERY_SEND,
	STUN_STATE_STUN_QUERY_WAIT,
};

struct network_stun_server {
	struct list_head list;

	struct avl_node pending_node;
	struct stun_request req;

	const char *host;
	uint8_t seq;
	bool req_auth_port;
	bool pending;
};

struct network_stun {
	struct list_head servers;
	struct avl_tree pending;

	struct uloop_timeout timer;

	enum network_stun_state state;
	bool wgport_disabled;

	uint16_t auth_port_ext;
	uint16_t port_local;
	uint16_t port_ext;

	int retry;

	struct uloop_fd socket;
};

enum pex_event {
	PEX_EV_HANDSHAKE,
	PEX_EV_ENDPOINT_CHANGE,
	PEX_EV_QUERY,
	PEX_EV_PING,
};

void network_pex_init(struct network *net);
int network_pex_open(struct network *net);
void network_pex_close(struct network *net);
void network_pex_free(struct network *net);
void network_pex_reload();

void network_pex_event(struct network *net, struct network_peer *peer,
		       enum pex_event ev);
struct network_pex_host *
network_pex_create_host(struct network *net, union network_endpoint *ep,
			unsigned int timeout);

void network_stun_init(struct network *net);
void network_stun_free(struct network *net);
void network_stun_server_add(struct network *net, const char *host);
void network_stun_rx_packet(struct network *net, const void *data, size_t len);
void network_stun_update_port(struct network *net, bool auth, uint16_t val);
void network_stun_start(struct network *net);

static inline bool network_pex_active(struct network_pex *pex)
{
	return pex->fd.fd >= 0;
}

int global_pex_open(const char *unix_path);

struct pex_hdr *pex_msg_init(struct network *net, uint8_t opcode);
struct pex_hdr *pex_msg_init_ext(struct network *net, uint8_t opcode, bool ext);
void pex_msg_send_ext(struct network *net, struct network_peer *peer,
					  struct sockaddr_in6 *addr);

#endif
