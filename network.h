// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_NETWORK_H
#define __UNETD_NETWORK_H

#include <netinet/in.h>
#include <libubox/uloop.h>
#include "curve25519.h"
#include "sntrup761.h"

enum network_type {
	NETWORK_TYPE_FILE,
	NETWORK_TYPE_INLINE,
	NETWORK_TYPE_DYNAMIC,
};

struct wg_ops;
struct network_group;
struct network_host;

struct network {
	struct avl_node node;

	struct wg wg;

	struct {
		struct blob_attr *data;
		enum network_type type;
		int keepalive;
		uint8_t key[CURVE25519_KEY_SIZE];
		uint8_t pubkey[CURVE25519_KEY_SIZE];
		uint8_t auth_key[CURVE25519_KEY_SIZE];
		uint8_t pqc_sec[SNTRUP761_SEC_SIZE];
		bool has_pqc_sec;
		const char *file;
		const char *interface;
		const char *update_cmd;
		const char *domain;
		struct blob_attr *tunnels;
		struct blob_attr *net_data;
		struct blob_attr *local_network;
		struct blob_attr *auth_connect;
		struct blob_attr *peer_data;
	} config;

	struct {
		uint64_t hash;
		union network_addr addr;
		struct network_host *local_host;
		unsigned int keepalive;
		int port;
		int pex_port;
		bool local_host_changed;
		struct blob_attr *stun_list;
	} net_config;

	void *net_data;
	size_t net_data_len;
	uint64_t net_data_version;
	int num_net_queries;
	unsigned int update_refused;

	struct uloop_timeout reload_timer;

	int ifindex;
	struct network_host *prev_local_host;

	struct list_head dynamic_peers;
	struct avl_tree hosts;
	struct vlist_tree peers;

	struct avl_tree groups;
	struct vlist_tree services;

	struct uloop_timeout connect_timer;

	struct network_pex pex;
	struct network_stun stun;
};

enum {
	NETWORK_ATTR_NAME,
	NETWORK_ATTR_TYPE,
	NETWORK_ATTR_KEY,
	NETWORK_ATTR_PQC_KEY,
	NETWORK_ATTR_AUTH_KEY,
	NETWORK_ATTR_FILE,
	NETWORK_ATTR_DATA,
	NETWORK_ATTR_INTERFACE,
	NETWORK_ATTR_UPDATE_CMD,
	NETWORK_ATTR_KEEPALIVE,
	NETWORK_ATTR_DOMAIN,
	NETWORK_ATTR_TUNNELS,
	NETWORK_ATTR_LOCAL_NET,
	NETWORK_ATTR_AUTH_CONNECT,
	NETWORK_ATTR_PEER_DATA,
	__NETWORK_ATTR_MAX,
};

extern struct avl_tree networks;
extern const struct blobmsg_policy network_policy[__NETWORK_ATTR_MAX];

static inline const char *network_name(struct network *net)
{
	return net->node.key;
}

void network_get_config(struct network *net, struct blob_buf *buf);
bool network_skip_endpoint_route(struct network *net, union network_endpoint *ep);
void network_fill_host_addr(union network_addr *addr, uint8_t *key);
int network_save_dynamic(struct network *net);
void network_soft_reload(struct network *net);
void network_free_all(void);

int unetd_network_add(const char *name, struct blob_attr *config);
int unetd_network_remove(const char *name);

#endif
