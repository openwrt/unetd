// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2024 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include "enroll.h"
#include "curve25519.h"
#include "sha512.h"
#include "chacha20.h"
#include "unetd.h"
#include <libubus.h>
#include <libubox/blobmsg_json.h>

#define CHAINING_KEY_STR "unetd enroll"

static struct enroll_state *state;
static uint8_t chaining_hash[SHA512_HASH_SIZE];
static struct blob_buf b;

enum msg_id {
	MSG_ID_C_DISCOVERY,
	MSG_ID_S_DISCOVERY,
	MSG_ID_C_ANNOUNCE,
	MSG_ID_S_CONFIRM,
	MSG_ID_C_ACCEPT,
	__MSG_ID_MAX
};

static const char * const msg_op_names[] = {
	[MSG_ID_C_DISCOVERY] = "discovery",
	[MSG_ID_C_ANNOUNCE] = "announce",
	[MSG_ID_C_ACCEPT] = "accept",
	[MSG_ID_S_DISCOVERY] = "discovery",
	[MSG_ID_S_CONFIRM] = "confirm",
};

struct enroll_msg_hdr {
	uint8_t op;
	uint8_t pubkey[CURVE25519_KEY_SIZE];
	uint8_t hmac[ENROLL_HASH_SIZE];
	uint8_t nonce[8];
};

struct enroll_msg_key_data {
	struct {
		uint8_t session_key[CURVE25519_KEY_SIZE];
		uint8_t op;
	} state;
	uint8_t data_key[SHA512_HASH_SIZE];
	uint8_t session_id[ENROLL_SESSION_ID_LEN];
};

enum {
	ENROLL_ATTR_KEY,
	ENROLL_ATTR_HASH,
	ENROLL_ATTR_SECRET,
	ENROLL_ATTR_INFO,
	__ENROLL_ATTR_MAX
};

static const struct blobmsg_policy enroll_policy[__ENROLL_ATTR_MAX] = {
	[ENROLL_ATTR_KEY] = { "key", BLOBMSG_TYPE_STRING },
	[ENROLL_ATTR_HASH] = { "hash", BLOBMSG_TYPE_STRING },
	[ENROLL_ATTR_SECRET] = { "secret", BLOBMSG_TYPE_STRING },
	[ENROLL_ATTR_INFO] = { "info", BLOBMSG_TYPE_TABLE },
};

struct blob_attr *tb[__ENROLL_ATTR_MAX];

static void
blobmsg_add_key(struct blob_buf *buf, const char *name, const uint8_t *key)
{
	size_t keystr_len = B64_ENCODE_LEN(CURVE25519_KEY_SIZE);
	char *str;

	str = blobmsg_alloc_string_buffer(buf, name, keystr_len);
	b64_encode(key, CURVE25519_KEY_SIZE, str, keystr_len);
	blobmsg_add_string_buffer(buf);
}

static int enroll_peer_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, CURVE25519_KEY_SIZE);
}

static void enroll_global_init(void)
{
	static bool init_done = false;
	struct sha512_state s;

	if (init_done)
		return;

	sha512_init(&s);
	sha512_add(&s, CHAINING_KEY_STR, sizeof(CHAINING_KEY_STR));
	sha512_final(&s, chaining_hash);
	init_done = true;
}

static inline bool is_server_msg(uint8_t op)
{
	switch (op) {
	case MSG_ID_S_DISCOVERY:
	case MSG_ID_S_CONFIRM:
		return true;
	default:
		return false;
	}
}

static bool
enroll_parse_b64(uint8_t *dest, struct blob_attr *attr, size_t len)
{
	if (!attr)
		return false;

	return b64_decode(blobmsg_get_string(attr), dest, len) == len;
}

static bool
enroll_parse_key(uint8_t *key)
{
	return enroll_parse_b64(key, tb[ENROLL_ATTR_KEY], CURVE25519_KEY_SIZE);
}

static bool
enroll_parse_hash(uint8_t *hash)
{
	return enroll_parse_b64(hash, tb[ENROLL_ATTR_HASH], ENROLL_HASH_SIZE);
}

static bool
enroll_parse_secret(uint8_t *hash)
{
	return enroll_parse_b64(hash, tb[ENROLL_ATTR_SECRET], ENROLL_HASH_SIZE);
}

static void
enroll_add_b64(const char *name, const void *data, size_t len)
{
	size_t str_len = B64_ENCODE_LEN(len);
	char *str;

	str = blobmsg_alloc_string_buffer(&b, name, str_len);
	b64_encode(data, len, str, str_len);
	blobmsg_add_string_buffer(&b);
}

static void
blobmsg_add_ipaddr(struct blob_buf *buf, const char *name, const void *addr)
{
	const struct sockaddr *sa = addr;
	int af = sa->sa_family;
	int addr_len;
	char *str;

	addr = network_endpoint_addr((void *)addr, &addr_len);
	str = blobmsg_alloc_string_buffer(buf, name, INET6_ADDRSTRLEN);
	inet_ntop(af, addr, str, INET6_ADDRSTRLEN);
	blobmsg_add_string_buffer(buf);
}

static void
enroll_add_hash(const uint8_t *hash)
{
	enroll_add_b64("hash", hash, ENROLL_HASH_SIZE);
}

static void
enroll_add_secret(const uint8_t *hash)
{
	enroll_add_b64("secret", hash, ENROLL_HASH_SIZE);
}

static void
enroll_add_key(const uint8_t *key)
{
	enroll_add_b64("key", key, CURVE25519_KEY_SIZE);
}

static void
enroll_add_info(struct blob_attr *attr)
{
	const void *data;
	size_t len;

	if (attr) {
		data = blobmsg_data(attr);
		len = blobmsg_data_len(attr);
	} else {
		data = "";
		len = 0;
	}

	blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "info", data, len);
}

static void
enroll_calc_session_keys(struct enroll_msg_key_data *key_data,
			 uint8_t op, const uint8_t *pubkey)
{
	uint8_t pubkeys[CURVE25519_KEY_SIZE];
	uint8_t hmac[SHA512_HASH_SIZE];

	key_data->state.op = op;
	curve25519(key_data->state.session_key, state->privkey, pubkey);

	memcpy(pubkeys, pubkey, CURVE25519_KEY_SIZE);
	for (size_t i = 0; i < CURVE25519_KEY_SIZE; i++)
		pubkeys[i] ^= state->pubkey[i];
	hmac_sha512(hmac, chaining_hash, sizeof(chaining_hash),
		    pubkeys, sizeof(pubkeys));
	hmac_sha512(hmac, hmac, sizeof(hmac),
		    &key_data->state, sizeof(key_data->state));
	memcpy(key_data->data_key, hmac, sizeof(key_data->data_key));

	hmac_sha512(hmac, chaining_hash, sizeof(chaining_hash),
		    &key_data->state.session_key, sizeof(key_data->state.session_key));
	memcpy(key_data->session_id, hmac, sizeof(key_data->session_id));
}

static void
enroll_peer_free(struct enroll_peer *peer)
{
	avl_delete(&state->peers, &peer->node);
	free(peer->enroll_meta);
	free(peer);
}

static void
enroll_msg_send(uint8_t op, struct blob_attr *msg,
		const uint8_t *pubkey, struct sockaddr_in6 *addr)
{
	struct enroll_msg_key_data key_data = {};
	uint8_t hmac[SHA512_HASH_SIZE];
	struct enroll_msg_hdr *hdr;
	static struct blob_buf b;
	uint64_t nonce;
	size_t len = 0;
	void *data;
	char *str;

	__pex_msg_init(state->pubkey, PEX_MSG_ENROLL);
	pex_msg_append(sizeof(struct pex_ext_hdr));

	hdr = pex_msg_append(sizeof(*hdr));
	hdr->op = op;
	memcpy(hdr->pubkey, state->pubkey, sizeof(hdr->pubkey));

	if (!msg)
		goto out;

	len = blobmsg_data_len(msg);
	data = pex_msg_append(len);
	if (!data) {
		D("message too large");
		return;
	}

	memcpy(data, blobmsg_data(msg), len);

	enroll_calc_session_keys(&key_data, op, pubkey);

	nonce = cpu_to_be64(state->nonce);
	memcpy(hdr->nonce, &nonce, sizeof(hdr->nonce));
	state->nonce++;

	chacha20_encrypt_msg(data, len, hdr->nonce, key_data.data_key);

	hmac_sha512(hmac, key_data.data_key, sizeof(key_data.data_key), data, len);
	memcpy(hdr->hmac, hmac, sizeof(hdr->hmac));

out:
	blob_buf_init(&b, 0);
	blobmsg_add_ipaddr(&b, "address", addr);
	blobmsg_add_key(&b, "id", hdr->pubkey);
	if (msg)
		blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "data",
				  blobmsg_data(msg), blobmsg_data_len(msg));
	str = blobmsg_format_json(b.head, true);
	D("tx enroll %s %s: %s", is_server_msg(op) ? "server" : "client", msg_op_names[op], str);
	free(str);

	if (__pex_msg_send(-1, addr, NULL, 0) < 0)
		D("enroll: pex_msg_send failed: %s", strerror(errno));
}

static struct enroll_peer *
enroll_get_peer(const struct enroll_msg_hdr *hdr,
		struct sockaddr_in6 *addr,
		struct enroll_msg_key_data *key_data,
		struct blob_attr *meta)
{
	struct enroll_peer *peer;
	uint64_t nonce;

	memcpy(&nonce, hdr->nonce, sizeof(nonce));
	nonce = be64_to_cpu(nonce);

	peer = avl_find_element(&state->peers, hdr->pubkey, peer, node);
	if (peer) {
		if (key_data && nonce <= peer->nonce) {
			D("replay detected");
			return NULL;
		}

		goto out;
	}

	if (!meta || !key_data || state->peers.count >= ENROLL_MAX_PEERS)
		return NULL;

	peer = calloc(1, sizeof(*peer) + blob_pad_len(meta));
	peer->node.key = peer->pubkey;
	memcpy(peer->pubkey, hdr->pubkey, sizeof(peer->pubkey));
	memcpy(peer->session_id, key_data->session_id, sizeof(peer->session_id));
	memcpy(peer->session_key, key_data->state.session_key, sizeof(peer->session_key));
	memcpy(peer->meta, meta, blob_pad_len(meta));
	avl_insert(&state->peers, &peer->node);

out:
	peer->addr = *addr;
	peer->nonce = nonce;

	return peer;
}

static void
enroll_peer_notify(struct enroll_peer *peer)
{
	blob_buf_init(&b, 0);
	enroll_peer_info(&b, peer);
	unetd_ubus_notify("enroll_peer_update", b.head);
}

static void
enroll_peer_derive_local_key(struct enroll_peer *peer, uint8_t *key)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, CHAINING_KEY_STR, sizeof(CHAINING_KEY_STR));
	sha512_add(&s, state->privkey, sizeof(state->privkey));
	sha512_add(&s, peer->pubkey, sizeof(peer->pubkey));
	memcpy(key, sha512_final_get(&s), CURVE25519_KEY_SIZE);
	curve25519_clamp_secret(key);
}

static void
enroll_send_client_discovery(struct sockaddr_in6 *addr)
{
	enroll_msg_send(MSG_ID_C_DISCOVERY, NULL, NULL, addr);
}

static void
enroll_send_server_discovery(const uint8_t *pubkey, struct sockaddr_in6 *addr,
			     struct blob_attr *meta)
{
	blob_buf_init(&b, 0);
	enroll_add_info(meta);
	enroll_msg_send(MSG_ID_S_DISCOVERY, b.head, pubkey, addr);
}

static void
enroll_recv_client_announce(const struct enroll_msg_hdr *hdr,
			 struct enroll_msg_key_data *key_data,
			 struct sockaddr_in6 *addr)
{
	uint8_t pubkey[CURVE25519_KEY_SIZE];
	uint8_t key_dh[CURVE25519_KEY_SIZE];
	uint8_t hmac[SHA512_HASH_SIZE];
	uint8_t msg_hash[ENROLL_HASH_SIZE];
	uint8_t secret_hash[ENROLL_HASH_SIZE];
	struct enroll_peer *peer;
	bool valid_secret = false;

	if (!tb[ENROLL_ATTR_INFO] ||
	    !enroll_parse_key(pubkey) || !enroll_parse_hash(msg_hash)) {
		D("Invalid client announce message");
		return;
	}

	curve25519(key_dh, state->privkey, pubkey);
	hmac_sha512(hmac, chaining_hash, sizeof(chaining_hash),
		    key_dh, sizeof(key_dh));
	if (memcmp(hmac, msg_hash, sizeof(msg_hash)) != 0) {
		D("Public key DH HMAC does not match");
		return;
	}

	if (state->has_secret && enroll_parse_secret(secret_hash)) {
		hmac_sha512(hmac, state->secret_hash, sizeof(state->secret_hash),
			    hdr->pubkey, sizeof(hdr->pubkey));
		hmac_sha512(hmac, hmac, sizeof(hmac), key_dh, sizeof(key_dh));
		curve25519_clamp_secret(hmac + CURVE25519_KEY_SIZE);
		curve25519_generate_public(hmac, hmac + CURVE25519_KEY_SIZE);
		valid_secret = !memcmp(hmac, secret_hash, sizeof(secret_hash));
	}

	peer = enroll_get_peer(hdr, addr, key_data, tb[ENROLL_ATTR_INFO]);
	if (!peer)
		return;

	memcpy(peer->enroll_key, pubkey, sizeof(peer->enroll_key));
	peer->has_key = true;
	peer->has_secret = valid_secret;
	enroll_peer_notify(peer);
	if (valid_secret && state->auto_accept)
		enroll_peer_accept(peer, NULL);
}

static void
enroll_send_client_announce(struct enroll_peer *peer, struct blob_attr *meta)
{
	uint8_t local_key[CURVE25519_KEY_SIZE];
	uint8_t pubkey[CURVE25519_KEY_SIZE];
	uint8_t hmac[SHA512_HASH_SIZE];

	blob_buf_init(&b, 0);

	enroll_peer_derive_local_key(peer, local_key);
	curve25519_generate_public(pubkey, local_key);
	enroll_add_key(pubkey);

	/*
	 * TMP_DH = DH(local_key, peer->pubkey));
	 * HASH = HMAC(chaining_hash, TMP_DH)
	 */
	curve25519(pubkey, local_key, peer->pubkey);
	hmac_sha512(hmac, chaining_hash, sizeof(chaining_hash),
		    pubkey, sizeof(pubkey));
	enroll_add_hash(hmac);

	/*
	 * SECRET_HASH = HMAC(chaining_hash, secret)
	 * SECRET_TMP = HMAC(SECRET_HASH, pubkey)
	 * SECRET = HMAC(SECRET_TMP, TMP_DH)
	 * SECRET_PUB = DH_PUB(SECRET[32-64])
	 */
	if (state->has_secret) {
		hmac_sha512(hmac, state->secret_hash, sizeof(state->secret_hash),
			    state->pubkey, sizeof(state->pubkey));
		hmac_sha512(hmac, hmac, sizeof(hmac), pubkey, sizeof(pubkey));
		curve25519_clamp_secret(hmac + CURVE25519_KEY_SIZE);
		curve25519_generate_public(hmac, hmac + CURVE25519_KEY_SIZE);
		enroll_add_secret(hmac);
	}

	enroll_add_info(meta);

	enroll_msg_send(MSG_ID_C_ANNOUNCE, b.head, peer->pubkey, &peer->addr);
}

static void
enroll_recv_client_accept(const struct enroll_msg_hdr *hdr,
		       struct enroll_msg_key_data *key_data,
		       struct sockaddr_in6 *addr)
{
	struct enroll_peer *peer;

	peer = enroll_get_peer(hdr, addr, NULL, NULL);
	if (!peer)
		return;

	if (peer->confirmed)
		return;

	peer->confirmed = true;
	enroll_peer_notify(peer);
}

static void
enroll_send_client_accept(struct enroll_peer *peer)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, peer->enroll_key, sizeof(peer->enroll_key));
	sha512_add(&s, peer->pubkey, sizeof(peer->pubkey));

	blob_buf_init(&b, 0);
	enroll_add_hash(sha512_final_get(&s));
	enroll_msg_send(MSG_ID_C_ACCEPT, b.head, peer->pubkey, &peer->addr);
}

static void
enroll_recv_server_discovery(const struct enroll_msg_hdr *hdr,
			  struct enroll_msg_key_data *key_data,
			  struct sockaddr_in6 *addr)
{
	struct enroll_peer *peer;

	if (!tb[ENROLL_ATTR_INFO]) {
		D("Invalid server discovery message");
		return;
	}

	peer = enroll_get_peer(hdr, addr, key_data, tb[ENROLL_ATTR_INFO]);
	if (!peer)
		return;

	enroll_send_client_announce(peer, state->meta);
	enroll_peer_notify(peer);
}

static void
enroll_recv_server_confirm(const struct enroll_msg_hdr *hdr,
			struct enroll_msg_key_data *key_data,
			struct sockaddr_in6 *addr)
{
	uint8_t auth_key[CURVE25519_KEY_SIZE];
	uint8_t secret_hash[ENROLL_HASH_SIZE];
	uint8_t hmac[SHA512_HASH_SIZE];
	struct enroll_peer *peer;

	if (!tb[ENROLL_ATTR_INFO] || !enroll_parse_key(auth_key)) {
		D("Invalid server confirm message");
		return;
	}

	peer = enroll_get_peer(hdr, addr, NULL, NULL);
	if (!peer)
		return;

	memcpy(peer->enroll_key, auth_key, sizeof(peer->enroll_key));
	free(peer->enroll_meta);
	peer->enroll_meta = blob_memdup(tb[ENROLL_ATTR_INFO]);
	peer->has_key = true;
	peer->confirmed = true;
	enroll_peer_notify(peer);

	if (state->has_secret && enroll_parse_secret(secret_hash)) {
		hmac_sha512(hmac, state->pubkey, sizeof(state->pubkey),
			    state->secret_hash, sizeof(state->secret_hash));
		if (!memcmp(hmac, secret_hash, sizeof(secret_hash))) {
			peer->has_secret = true;
			if (state->auto_accept)
				peer->accepted = true;
		}
	}

	if (peer->accepted)
		enroll_peer_accept(peer, NULL);
}

static void
enroll_send_server_confirm(struct enroll_peer *peer, struct blob_attr *meta)
{
	uint8_t hmac[SHA512_HASH_SIZE];

	if (!meta)
		meta = state->enroll_meta;

	blob_buf_init(&b, 0);
	enroll_add_info(meta);
	enroll_add_key(state->net->config.auth_key);
	if (peer->has_secret) {
		/*
		 * SECRET_TMP = HMAC(chaining_hash, secret)
		 * SECRET = HMAC(peer->pubkey, SECRET_TMP)
		 */
		hmac_sha512(hmac, peer->pubkey, sizeof(peer->pubkey),
			    state->secret_hash, sizeof(state->secret_hash));
		enroll_add_secret(hmac);
	}
	enroll_msg_send(MSG_ID_S_CONFIRM, b.head, peer->pubkey, &peer->addr);
}


void pex_enroll_recv(void *data, size_t len, struct sockaddr_in6 *addr)
{
	const struct enroll_msg_hdr *hdr = data;
	struct enroll_msg_key_data key_data = {};
	uint8_t hmac[SHA512_HASH_SIZE];
	bool server_msg;
	char *msg_str;

	if (!state || len < sizeof(struct enroll_msg_hdr))
		return;

	data += sizeof(*hdr);
	len -= sizeof(*hdr);

	if (!memcmp(hdr->pubkey, state->pubkey, sizeof(hdr->pubkey)))
		return;

	if (hdr->op != MSG_ID_C_DISCOVERY) {
		if (!len)
			return;

		enroll_calc_session_keys(&key_data, hdr->op, hdr->pubkey);
		hmac_sha512(hmac, key_data.data_key, sizeof(key_data.data_key),
			    data, len);

		if (memcmp(hmac, hdr->hmac, sizeof(hdr->hmac)) != 0) {
			D("Invalid HMAC in enroll msg, op=%d", hdr->op);
			return;
		}

		chacha20_encrypt_msg(data, len, hdr->nonce, key_data.data_key);

		if (blobmsg_parse(enroll_policy, __ENROLL_ATTR_MAX, tb,
				  data, len)) {
			D("Invalid data in enroll msg, op=%d", hdr->op);
			return;
		}
	}

	if (hdr->op >= ARRAY_SIZE(msg_op_names) || !msg_op_names[hdr->op]) {
		D("Unknown enroll message id, op=%d\n", hdr->op);
		return;
	}

	server_msg = is_server_msg(hdr->op);

	blob_buf_init(&b, 0);
	blobmsg_add_ipaddr(&b, "address", addr);
	blobmsg_add_key(&b, "id", hdr->pubkey);
	if (hdr->op != MSG_ID_C_DISCOVERY)
		blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "data", data, len);
	msg_str = blobmsg_format_json(b.head, true);
	D("rx enroll %s %s: %s", server_msg ? "server" : "client", msg_op_names[hdr->op], msg_str);
	free(msg_str);

	if (server_msg != !state->net)
		return;

	switch (hdr->op) {
	case MSG_ID_C_DISCOVERY:
		if (enroll_get_peer(hdr, addr, NULL, NULL))
		    return;
		enroll_send_server_discovery(hdr->pubkey, addr, state->meta);
		return;
	case MSG_ID_C_ANNOUNCE:
		return enroll_recv_client_announce(hdr, &key_data, addr);
	case MSG_ID_C_ACCEPT:
		return enroll_recv_client_accept(hdr, &key_data, addr);
	case MSG_ID_S_DISCOVERY:
		return enroll_recv_server_discovery(hdr, &key_data, addr);
	case MSG_ID_S_CONFIRM:
		return enroll_recv_server_confirm(hdr, &key_data, addr);
	default:
		D("Invalid enroll msg, op=%d\n", hdr->op);
		break;
	}
}

void enroll_net_cleanup(struct network *net)
{
	if (state && state->net == net)
		enroll_stop();
}

void enroll_peer_info(struct blob_buf *buf, struct enroll_peer *peer)
{
	uint8_t local_key[CURVE25519_KEY_SIZE];
	uint8_t local_pubkey[CURVE25519_KEY_SIZE];

	blobmsg_add_key(buf, "id", peer->pubkey);
	blobmsg_printf(buf, "session", "%08x", be32_to_cpu(*(uint32_t *)peer->session_id));
	blobmsg_add_ipaddr(buf, "address", &peer->addr);

	if (!state->net) {
		enroll_peer_derive_local_key(peer, local_key);
		blobmsg_add_key(buf, "local_key", local_key);
		curve25519_generate_public(local_pubkey, local_key);
		blobmsg_add_key(buf, "local_pubkey", local_pubkey);
	}
	if (peer->has_key)
		blobmsg_add_key(buf, "enroll_key", peer->enroll_key);
	if (peer->enroll_meta)
		blobmsg_add_field(buf, BLOBMSG_TYPE_TABLE, "enroll_meta",
				  blobmsg_data(peer->enroll_meta),
				  blobmsg_data_len(peer->enroll_meta));

	blobmsg_add_u8(buf, "confirmed", peer->confirmed);
	blobmsg_add_u8(buf, "accepted", peer->accepted);
	blobmsg_add_u8(buf, "has_secret", peer->has_secret);
}

void enroll_peer_accept(struct enroll_peer *peer, struct blob_attr *meta)
{
	peer->accepted = true;
	enroll_peer_notify(peer);
	if (state->net) {
		enroll_send_server_confirm(peer, meta);
		return;
	}

	if (!peer->has_key)
		return;

	enroll_send_client_accept(peer);
	uloop_timeout_cancel(&state->connect_timer);
}

static void enroll_timeout_cb(struct uloop_timeout *t)
{
	blob_buf_init(&b, 0);
	unetd_ubus_notify("enroll_timeout", b.head);
	enroll_stop();
}

struct enroll_state *enroll_state(void)
{
	return state;
}

static void connect_timer_cb(struct uloop_timeout *t)
{
	uloop_timeout_set(t, state->connect_interval);

	for (size_t i = 0; i < state->n_connect; i++)
		enroll_send_client_discovery(&state->connect[i].in6);
}

const struct blobmsg_policy enroll_start_policy[__ENROLL_START_ATTR_MAX] = {
	[ENROLL_START_ATTR_NETWORK] = { "network", BLOBMSG_TYPE_STRING },
	[ENROLL_START_ATTR_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
	[ENROLL_START_ATTR_CONNECT] = { "connect", BLOBMSG_TYPE_ARRAY },
	[ENROLL_START_ATTR_INTERVAL] = { "interval", BLOBMSG_TYPE_INT32 },
	[ENROLL_START_ATTR_ENROLL_AUTO] = { "enroll_auto", BLOBMSG_TYPE_BOOL },
	[ENROLL_START_ATTR_ENROLL_SECRET] = { "enroll_secret", BLOBMSG_TYPE_STRING },
	[ENROLL_START_ATTR_ENROLL_INFO] = { "enroll_info", BLOBMSG_TYPE_TABLE },
	[ENROLL_START_ATTR_INFO] = { "info", BLOBMSG_TYPE_TABLE },
};

int enroll_start(struct blob_attr *data)
{
	struct blob_attr *tb[__ENROLL_START_ATTR_MAX], *cur;
	struct blob_attr *meta, *enroll_meta, *remote;
	struct blob_attr *meta_buf, *enroll_meta_buf;
	unsigned int timeout, interval;
	struct network *net = NULL;
	int n_connect = 0, err = 0;
	size_t rem;
	FILE *f;

	enroll_stop();
	blobmsg_parse_attr(enroll_start_policy, __ENROLL_START_ATTR_MAX, tb, data);

	if ((cur = tb[ENROLL_START_ATTR_NETWORK]) != NULL) {
		const char *name = blobmsg_get_string(cur);

		net = avl_find_element(&networks, name, net, node);
		if (!net)
			return UBUS_STATUS_NOT_FOUND;
	}

	if ((cur = tb[ENROLL_START_ATTR_TIMEOUT]) != NULL)
		timeout = blobmsg_get_u32(cur);
	else
		timeout = 120;

	if (net)
		interval = 0;
	else if ((cur = tb[ENROLL_START_ATTR_INTERVAL]) != NULL)
		interval = blobmsg_get_u32(cur);
	else
		interval = 10;

	blob_buf_init(&b, 0);
	meta = tb[ENROLL_START_ATTR_INFO];
	if (!meta)
		meta = b.head;

	enroll_meta = tb[ENROLL_START_ATTR_ENROLL_INFO];
	if (!enroll_meta)
		enroll_meta = b.head;

	remote = tb[ENROLL_START_ATTR_CONNECT];
	if (remote) {
		n_connect = blobmsg_check_array(remote, BLOBMSG_TYPE_STRING);
		if (n_connect < 0)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	enroll_global_init();
	state = calloc_a(sizeof(*state) + n_connect * sizeof(state->connect[0]),
			 &meta_buf, blob_pad_len(meta),
			 &enroll_meta_buf, blob_pad_len(enroll_meta));
	state->net = net;
	state->connect_interval = interval * 1000;
	avl_init(&state->peers, enroll_peer_cmp, false, NULL);
	state->meta = memcpy(meta_buf, meta, blob_pad_len(meta));
	state->enroll_meta = memcpy(enroll_meta_buf, enroll_meta, blob_pad_len(enroll_meta));

	blobmsg_for_each_attr(cur, remote, rem) {
		if (network_get_endpoint(&state->connect[state->n_connect],
					 AF_UNSPEC, blobmsg_get_string(cur),
					 UNETD_GLOBAL_PEX_PORT, 0))
			continue;

		state->n_connect++;
	}

	f = fopen("/dev/urandom", "r");
	if (!f)
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (fread(state->privkey, sizeof(state->privkey), 1, f) != 1)
	    err = UBUS_STATUS_UNKNOWN_ERROR;

	fclose(f);
	if (err)
	    goto error;

	curve25519_clamp_secret(state->privkey);
	curve25519_generate_public(state->pubkey, state->privkey);

	if ((cur = tb[ENROLL_START_ATTR_ENROLL_SECRET]) != NULL) {
		const char *str = blobmsg_get_string(cur);

		hmac_sha512(state->secret_hash, chaining_hash, sizeof(chaining_hash),
			    str, strlen(str));
		state->has_secret = true;
		if ((cur = tb[ENROLL_START_ATTR_ENROLL_AUTO]) != NULL)
		    state->auto_accept = blobmsg_get_bool(cur);
	}

	state->timeout.cb = enroll_timeout_cb;
	if (timeout)
		uloop_timeout_set(&state->timeout, timeout * 1000);
	state->connect_timer.cb = connect_timer_cb;
	if (interval && state->n_connect)
		uloop_timeout_set(&state->connect_timer, 10);

	return 0;

error:
	free(state);
	state = NULL;
	return err;
}

void enroll_stop(void)
{
	struct enroll_peer *p, *tmp;

	if (!state)
		return;

	avl_for_each_element_safe(&state->peers, p, node, tmp)
		enroll_peer_free(p);

	uloop_timeout_cancel(&state->timeout);
	uloop_timeout_cancel(&state->connect_timer);
	free(state);
	state = NULL;
}
