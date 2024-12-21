// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __ENROLL_H
#define __ENROLL_H

#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <libubox/avl.h>
#include "utils.h"
#include "curve25519.h"
#include "sha512.h"

#define ENROLL_SESSION_ID_LEN 4
#define ENROLL_HASH_SIZE 32

#define ENROLL_MAX_PEERS 64

struct network;

struct enroll_peer {
	struct avl_node node;

	struct sockaddr_in6 addr;
	uint64_t nonce;

	uint8_t session_id[ENROLL_SESSION_ID_LEN];
	uint8_t session_key[CURVE25519_KEY_SIZE];
	uint8_t pubkey[CURVE25519_KEY_SIZE];

	struct blob_attr *enroll_meta;
	uint8_t enroll_key[CURVE25519_KEY_SIZE];

	bool has_secret;
	bool has_key;
	bool confirmed;
	bool accepted;

	struct blob_attr meta[];
};

struct enroll_state {
	struct network *net;

	struct avl_tree peers;

	struct uloop_timeout timeout;
	struct uloop_timeout connect_timer;
	uint8_t privkey[2 * CURVE25519_KEY_SIZE];
	uint8_t pubkey[CURVE25519_KEY_SIZE];
	uint64_t nonce;

	struct blob_attr *meta;
	struct blob_attr *enroll_meta;

	uint8_t secret_hash[SHA512_HASH_SIZE];
	bool has_secret;
	bool auto_accept;

	unsigned int connect_interval;
	unsigned int n_connect;
	union network_endpoint connect[];
};

enum {
	ENROLL_START_ATTR_NETWORK,
	ENROLL_START_ATTR_TIMEOUT,
	ENROLL_START_ATTR_CONNECT,
	ENROLL_START_ATTR_INTERVAL,
	ENROLL_START_ATTR_ENROLL_AUTO,
	ENROLL_START_ATTR_ENROLL_SECRET,
	ENROLL_START_ATTR_ENROLL_INFO,
	ENROLL_START_ATTR_INFO,
	__ENROLL_START_ATTR_MAX,
};

#ifdef UBUS_SUPPORT

extern const struct blobmsg_policy enroll_start_policy[__ENROLL_START_ATTR_MAX];

void pex_enroll_recv(void *data, size_t len, struct sockaddr_in6 *addr);

struct enroll_state *enroll_state(void);
void enroll_net_cleanup(struct network *net);
void enroll_peer_info(struct blob_buf *buf, struct enroll_peer *peer);
void enroll_peer_accept(struct enroll_peer *peer, struct blob_attr *meta);
int enroll_start(struct blob_attr *data);
void enroll_stop(void);

#else

static inline void pex_enroll_recv(void *data, size_t len, struct sockaddr_in6 *addr)
{
}

static inline void enroll_net_cleanup(struct network *net)
{
}

#endif

#endif
