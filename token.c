// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Felix Fietkau <nbd@nbd.name>
 */
#include <time.h>
#include "unetd.h"
#include "sha512.h"
#include "random.h"

static uint8_t salt[8];
static uint64_t nonce;

struct token_hdr {
	uint8_t src[PEX_ID_LEN];
	uint8_t salt[8];
	uint64_t nonce;
	uint8_t hmac[SHA512_HASH_SIZE / 2];
};

static bool token_init(void)
{
	static bool init_done;

	if (init_done)
		return true;

	init_done = true;
	randombytes(salt, sizeof(salt));

	return init_done;
}


static bool
token_verify_service(struct network *net, const char *name,
		     struct network_host *local_host,
		     struct network_host *target)
{
	struct network_service *s;
	bool dest_found = false;
	bool src_found = false;

	s = vlist_find(&net->services, name, s, node);
	if (!s)
		return false;

	for (size_t i = 0; i < s->n_members; i++) {
		if (s->members[i] == local_host)
			src_found = true;
		if (s->members[i] == target)
			dest_found = true;
	}

	if (!src_found || !dest_found)
		return false;

	return true;
}


void *token_create(struct network *net, struct network_host *target,
		   const char *service, struct blob_attr *info, size_t *len)
{
	struct network_host *local_host = net->net_config.local_host;
	size_t data_len = blob_pad_len(info);
	uint8_t dh_key[CURVE25519_KEY_SIZE];
	uint8_t hmac[SHA512_HASH_SIZE];
	struct sha512_state s;
	struct token_hdr *hdr;
	const void *key;
	void *data;

	if (!local_host || !token_init() || target == local_host)
		return NULL;

	if (service && !token_verify_service(net, service, local_host, target))
		return NULL;

	hdr = data = malloc(sizeof(*hdr) + data_len);
	data += sizeof(*hdr);

	memcpy(hdr->src, local_host->peer.key, sizeof(hdr->src));
	memcpy(hdr->salt, salt, sizeof(hdr->salt));
	hdr->nonce = nonce++;

	curve25519(dh_key, net->config.key, target->peer.key);
	sha512_init(&s);
	sha512_add(&s, dh_key, sizeof(dh_key));
	sha512_add(&s, salt, sizeof(salt));
	key = sha512_final_get(&s);

	memcpy(data, info, data_len);
	chacha20_encrypt_msg(data, data_len, &hdr->nonce, key);

	hmac_sha512(hmac, key, SHA512_HASH_SIZE, data, data_len);
	memcpy(hdr->hmac, hmac, sizeof(hdr->hmac));

	*len = data_len + sizeof(*hdr);

	return hdr;
}

static bool
token_decrypt(struct network *net, struct token_hdr *hdr, size_t len,
	      struct network_host **host)
{
	struct network_host *local_host = net->net_config.local_host;
	uint8_t dh_key[CURVE25519_KEY_SIZE];
	uint8_t pubkey[WG_KEY_LEN] = {};
	uint8_t hmac[SHA512_HASH_SIZE];
	struct network_peer *peer;
	struct sha512_state s;
	const void *key;
	void *data;

	data = hdr + 1;
	memcpy(pubkey, hdr->src, sizeof(hdr->src));
	peer = avl_find_ge_element(&net->peers.avl, pubkey, peer, node.avl);
	if (!peer || peer == &local_host->peer)
		return false;

	if (memcmp(peer->key, pubkey, sizeof(hdr->src)) != 0)
		return false;

	memcpy(pubkey, peer->key, sizeof(pubkey));
	curve25519(dh_key, net->config.key, pubkey);
	sha512_init(&s);
	sha512_add(&s, dh_key, sizeof(dh_key));
	sha512_add(&s, hdr->salt, sizeof(hdr->salt));
	key = sha512_final_get(&s);

	hmac_sha512(hmac, key, SHA512_HASH_SIZE, data, len);
	if (memcmp(hdr->hmac, hmac, sizeof(hdr->hmac)) != 0)
		return false;

	chacha20_encrypt_msg(data, len, &hdr->nonce, key);
	*host = container_of(peer, struct network_host, peer);

	return true;
}

bool token_parse(struct blob_buf *buf, const char *token)
{
	enum {
		TOKEN_ATTR_SERVICE,
		__TOKEN_ATTR_MAX,
	};
	struct blobmsg_policy policy[__TOKEN_ATTR_MAX] = {
		[TOKEN_ATTR_SERVICE] = { "service", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__TOKEN_ATTR_MAX], *cur;
	struct network_host *host;
	struct token_hdr *hdr;
	struct network *net;
	bool ret = false;
	size_t len;
	void *data;

	len = B64_DECODE_LEN(strlen(token));
	hdr = malloc(len);
	len = b64_decode(token, hdr, len);
	if (len <= sizeof(*hdr) + sizeof(struct blob_attr))
		goto out;

	data = hdr + 1;
	len -= sizeof(*hdr);
	avl_for_each_element(&networks, net, node) {
		struct network_host *local_host = net->net_config.local_host;

		if (!local_host)
			continue;

		ret = token_decrypt(net, hdr, len, &host);
		if (!ret)
			continue;

		blobmsg_add_string(buf, "network", network_name(net));
		blobmsg_add_string(buf, "host", network_host_name(host));

		if (blob_pad_len(data) != len) {
			ret = false;
			break;
		}

		blobmsg_parse_attr(policy, __TOKEN_ATTR_MAX, tb, data);

		cur = tb[TOKEN_ATTR_SERVICE];
		if (cur && !token_verify_service(net, blobmsg_get_string(cur),
						 local_host, host))
			ret = false;
		break;
	}
	if (!ret)
		goto out;


	blob_put_raw(buf, blobmsg_data(data), blobmsg_len(data));

out:
	free(hdr);
	return ret;
}
