
#include "chacha20.h"
#include "curve25519.h"
#include "host.h"
#include "network.h"
#include "pex.h"
#include "pex-msg.h"
#include "psk-kex.h"
#include "random.h"
#include "sha512.h"
#include "siphash.h"
#include "sntrup761.h"
#include "unetd.h"
#include "utils.h"
#include "wg.h"
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include "libubox/vlist.h"

#define KEX_LABEL		"WG PQ PSK sntrup761"
#define HANDSHAKE_INTERVAL 	120

static uint8_t kex_hash[SHA512_HASH_SIZE];


static enum psk_kex_role
psk_kex_determine_role(struct network *net, struct network_peer *peer)
{
	int cmp = memcmp(net->config.pubkey, peer->key, CURVE25519_KEY_SIZE);
	if (cmp > 0) {
		return PSK_KEX_ROLE_INITIATOR;
	} else if (cmp < 0) {
		return PSK_KEX_ROLE_RESPONDER;
	} else {
		return PSK_KEX_ROLE_NONE;
	}
}

static void
psk_kex_keygen(uint8_t *dest, const void *src, size_t len)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, kex_hash, sizeof(kex_hash));
	sha512_add(&s, src, len);
	memcpy(dest, sha512_final_get(&s), CHACHA20_KEY_SIZE);
}

static void
psk_kex_encrypt(uint8_t *dest, size_t len, uint8_t *mac, const uint8_t *nonce, const uint8_t *key)
{
	siphash_key_t mac_key;

	memcpy(&mac_key, key, sizeof(mac_key));
	chacha20_encrypt_msg(dest, len, nonce, key);
	siphash_to_le64(mac, dest, len, &mac_key);
}

static bool
psk_kex_decrypt(uint8_t *dest, size_t len, const uint8_t *mac, const uint8_t *nonce, const uint8_t *key)
{
	uint8_t check_mac[MAC_LEN];
	siphash_key_t mac_key;

	memcpy(&mac_key, key, sizeof(mac_key));
	siphash_to_le64(check_mac, dest, len, &mac_key);
	if (memcmp(check_mac, mac, sizeof(check_mac)) != 0)
		return false;

	chacha20_encrypt_msg(dest, len, nonce, key);
	return true;
}

static void
psk_kex_derive_psk(struct psk_kex_ctx *ctx, uint8_t *psk)
{
	struct sha512_state sha;

	sha512_init(&sha);
	sha512_add(&sha, kex_hash, sizeof(kex_hash));
	sha512_add(&sha, ctx->k1, sizeof(ctx->k1));
	sha512_add(&sha, ctx->k2, sizeof(ctx->k2));
	sha512_add(&sha, ctx->k3, sizeof(ctx->k3));

	memcpy(psk, sha512_final_get(&sha), CHACHA20_KEY_SIZE);
}

static bool
psk_kex_need_handshake(struct network_peer *peer)
{
	time_t now = time(NULL);
	uint64_t last = peer->state.last_psk_handshake;

	return last == 0 || now - last > HANDSHAKE_INTERVAL;
}

void psk_kex_request_status_cb(struct uloop_timeout *t)
{
	struct network *net = container_of(t, struct network, pex.request_psk_kex_status_timer);
	struct network_peer *peer;

	D_NET(net, "in %s", __func__);

	uloop_timeout_set(t, HANDSHAKE_INTERVAL);

	D_NET(net, "Iterating over peers to request psk-kex status.");

	vlist_for_each_element(&net->peers, peer, node) {
		psk_kex_request_status(net, peer);
	}
}

static void
psk_kex_send_msg(struct network *net, struct network_peer *peer)
{
	struct sockaddr_in6 *addr = NULL;
	char addrbuf[INET6_ADDRSTRLEN];

	// FIXME: is it fine to just use the first valid address
	// 	or use the "most appropriate" one
	// 	or send to all unique endpoint addresses??

	for (int i = 0; i < __ENDPOINT_TYPE_MAX; i++) {
		union network_endpoint *ep = &peer->state.next_endpoint[i];

		if (!ep->in6.sin6_family) // AF_UNSPEC aka no address?
			continue;

		addr = &ep->in6;
		break;
	}

	if (!addr) {
		D_PEER(net, peer, "ERR no address to send to");
		return;
	}
	D_PEER(net, peer, "send msg to peer addr %s",
		inet_ntop(addr->sin6_family, (const void *)&addr->sin6_addr, addrbuf,
			sizeof(addrbuf)));
	pex_msg_send_ext(net, peer, addr);
}

void
psk_kex_request_status(struct network *net, struct network_peer *peer)
{
	struct pex_psk_kex_status *resp;

	if (peer->kex_ctx.state != KEX_STATE_IDLE)
		return;

	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_STATUS_REQUEST, true);
	resp = pex_msg_append(sizeof(struct pex_psk_kex_status));
	resp->last_handshake_time = peer->state.last_psk_handshake;
	resp->need_handshake = psk_kex_need_handshake(peer);

	psk_kex_send_msg(net, peer);
	peer->kex_ctx.state = KEX_STATE_WAITING_FOR_STATUS_RESPONSE;
}

/* TODO: split this to avoid doing crypto again and again when we need to retransmit */

static void
psk_kex_start_key_exchange(struct network *net, struct network_peer *peer)
{
	struct pex_psk_kex_initiator_msg_part1 *msg_a;
	struct pex_psk_kex_initiator_msg_part2 *msg_b;
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	D_PEER(net, peer, "in psk_kex_start_key_exchange");

	if (peer->kex_ctx.role != PSK_KEX_ROLE_INITIATOR)
		return;

	D_PEER(net, peer, "starting key exchange");

	/* First message (contains c1) */
	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_INITIATOR_MSG_PART1, true);
	msg_a = pex_msg_append(sizeof(struct pex_psk_kex_initiator_msg_part1));

	/* Generate ephemeral keypair */
	sntrup761_keypair(ctx->e_pub, ctx->e_sec);

	/* Generate k1 and encapsulate it with peer's public key */
	sntrup761_enc(msg_a->c1, ctx->k1, peer->pqc_pub);
	psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));

	D_PEER(net, peer, "sending first message to peer");
	psk_kex_send_msg(net, peer);

	/* Second message (contains encrypted ephemeral public key) */
	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_INITIATOR_MSG_PART2, true);
	msg_b = pex_msg_append(sizeof(struct pex_psk_kex_initiator_msg_part2));

	randombytes(&msg_b->nonce, sizeof(msg_b->nonce)); /* Generate a random nonce */
	memcpy(&msg_b->e_pub_enc, ctx->e_pub, sizeof(ctx->e_pub)); /* Copy the ephemeral public key to buf */
	psk_kex_encrypt(msg_b->e_pub_enc, sizeof(msg_b->e_pub_enc), msg_b->e_pub_mac, msg_b->nonce, key); /* Encrypt + MAC the ephemeral public key */

	D_PEER(net, peer, "sending second message to peer");
	psk_kex_send_msg(net, peer);

	peer->kex_ctx.state = KEX_STATE_WAITING_FOR_RESPONDER_MSG_PART1;
	return;
}

static void
psk_kex_finish_key_exchange(struct network *net, struct network_peer *peer)
{
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	enum psk_kex_role role;

	psk_kex_derive_psk(ctx, peer->psk);

	role = ctx->role;
	memset(ctx, 0, sizeof(struct psk_kex_ctx));
	ctx->role = role;

	peer->state.last_psk_handshake = time(NULL);
	wg_peer_update(net, peer, WG_PEER_UPDATE);
}

static void
psk_kex_recv_status_msg(struct network *net, struct network_peer *peer,
			struct pex_psk_kex_status *data, enum pex_opcode opcode)
{
	struct pex_psk_kex_status *resp;
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	bool we_need_handshake, peer_needs_handshake;

	D_PEER(net, peer, "received status message opcode %d", opcode);

	switch (opcode) {
	case PEX_MSG_PSK_KEX_STATUS_REQUEST:
		D_PEER(net, peer, "recv status request");

		/* if we're initiator, sent a request before and now receive one too,
		 * just drop that. Responder has to respond to our request. */
		if (ctx->state == KEX_STATE_WAITING_FOR_STATUS_RESPONSE && ctx->role == PSK_KEX_ROLE_INITIATOR)
			return;
		break;
	case PEX_MSG_PSK_KEX_STATUS_RESPONSE:
		D_PEER(net, peer, "recv status response");

		/* Don't accept a response coming out of nowhere */
		if (ctx->state != KEX_STATE_WAITING_FOR_STATUS_RESPONSE)
			return;
		break;
	default: return;
	}

	we_need_handshake = psk_kex_need_handshake(peer);
	peer_needs_handshake = data->need_handshake;
	D_PEER(net, peer, "handshake requirement: local %d remote %d", we_need_handshake, peer_needs_handshake);

	if (opcode == PEX_MSG_PSK_KEX_STATUS_REQUEST) {
		pex_msg_init_ext(net, PEX_MSG_PSK_KEX_STATUS_RESPONSE, true);
		resp = pex_msg_append(sizeof(struct pex_psk_kex_status));
		resp->last_handshake_time = peer->state.last_psk_handshake;
		resp->need_handshake = we_need_handshake;

		D_PEER(net, peer, "respond to status request");
		psk_kex_send_msg(net, peer);
	}

	/* do nothing in case no one needs a handshake */
	if (!we_need_handshake && !peer_needs_handshake)
		return;
	/* otherwise, always do a handshake */

	/* designated initiator has to initiate key exchange */
	if (ctx->role == PSK_KEX_ROLE_RESPONDER)
		return;

	/* do we need a delay here? we just sent the status response to the peer */
	psk_kex_start_key_exchange(net, peer);
	return;
}

static void
psk_kex_recv_initiator_msg_part1(struct network *net, struct network_peer *peer,
				 struct pex_psk_kex_initiator_msg_part1 *data)
{
	struct psk_kex_ctx *ctx = &peer->kex_ctx;

	if (ctx->role != PSK_KEX_ROLE_RESPONDER)
		return;

	sntrup761_dec(ctx->k1, data->c1, net->config.pqc_sec);
	ctx->state = KEX_STATE_WAITING_FOR_INITIATOR;
}

static void
psk_kex_recv_initiator_msg_part2(struct network *net, struct network_peer *peer,
				 struct pex_psk_kex_initiator_msg_part2 *data)
{
	struct pex_psk_kex_responder_msg *resp;
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	uint8_t nonce[CHACHA20_NONCE_SIZE];
	uint8_t key[CHACHA20_KEY_SIZE];

	if (ctx->role != PSK_KEX_ROLE_RESPONDER || ctx->state != KEX_STATE_WAITING_FOR_INITIATOR)
		return;

	psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));
	if (!psk_kex_decrypt(data->e_pub_enc, sizeof(data->e_pub_enc), data->e_pub_mac, data->nonce, key))
		return;
	memcpy(ctx->e_pub, data->e_pub_enc, sizeof(ctx->e_pub));

	// ####################################

	randombytes(nonce, sizeof(nonce));

	/* TBD: Can we send two (UDP) messages in a row without issues? */

	/* First message (contains c2 "encrypted" with e_pub) */
	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_RESPONDER_MSG_PART1, true);
	resp = pex_msg_append(sizeof(*resp));
	memcpy(&resp->nonce, nonce, sizeof(nonce));

	sntrup761_enc(resp->c_enc, ctx->k2, ctx->e_pub);
	psk_kex_encrypt(resp->c_enc, sizeof(resp->c_enc), resp->c_mac, resp->nonce, key);
	psk_kex_send_msg(net, peer);

	// ####################################

	/* Second message (contains c3 "encrypted" with peer's pubkey) */
	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_RESPONDER_MSG_PART2, true);
	resp = pex_msg_append(sizeof(*resp));
	memcpy(&resp->nonce, nonce, sizeof(nonce));

	sntrup761_enc(resp->c_enc, ctx->k3, peer->pqc_pub);
	psk_kex_keygen(key, ctx->k2, sizeof(ctx->k2));
	psk_kex_encrypt(resp->c_enc, sizeof(resp->c_enc), resp->c_mac, resp->nonce, key);

	psk_kex_send_msg(net, peer);
	psk_kex_finish_key_exchange(net, peer);
}

static void
psk_kex_recv_responder_msg(struct network *net, struct network_peer *peer,
			   enum pex_opcode opcode, struct pex_psk_kex_responder_msg *data)
{
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	switch (opcode) {
	case PEX_MSG_PSK_KEX_RESPONDER_MSG_PART1:
		if (ctx->state != KEX_STATE_WAITING_FOR_RESPONDER_MSG_PART1)
			return;

		psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));
		if (!psk_kex_decrypt(data->c_enc, sizeof(data->c_enc), data->c_mac, data->nonce, key))
			return;

		sntrup761_dec(ctx->k2, data->c_enc, ctx->e_sec);

		ctx->state = KEX_STATE_WAITING_FOR_RESPONDER_MSG_PART2;
		break;
	case PEX_MSG_PSK_KEX_RESPONDER_MSG_PART2:
		if (ctx->state != KEX_STATE_WAITING_FOR_RESPONDER_MSG_PART2)
			return;

		psk_kex_keygen(key, ctx->k2, sizeof(ctx->k2));
		if (!psk_kex_decrypt(data->c_enc, sizeof(data->c_enc), data->c_mac, data->nonce, key))
			return;

		sntrup761_dec(ctx->k3, data->c_enc, net->config.pqc_sec);

		psk_kex_finish_key_exchange(net, peer);
		break;
	default: return;
	}
}

void psk_kex_recv_msg(struct network *net, struct network_peer *peer, enum pex_opcode opcode, const void *data, size_t len)
{
	if (peer->kex_ctx.role == PSK_KEX_ROLE_NONE)
		return;

	D_PEER(net, peer, "received pex psk-kex message");

	switch (opcode) {
	case PEX_MSG_PSK_KEX_STATUS_REQUEST:
	case PEX_MSG_PSK_KEX_STATUS_RESPONSE:
		if (len < sizeof(struct pex_psk_kex_status))
			return;

		psk_kex_recv_status_msg(net, peer, (struct pex_psk_kex_status *)data, opcode);
		return;
	case PEX_MSG_PSK_KEX_INITIATOR_MSG_PART1:
		if (len < sizeof(struct pex_psk_kex_initiator_msg_part1))
			return;

		psk_kex_recv_initiator_msg_part1(net, peer, (struct pex_psk_kex_initiator_msg_part1 *)data);
		break;
	case PEX_MSG_PSK_KEX_INITIATOR_MSG_PART2:
		if (len < sizeof(struct pex_psk_kex_initiator_msg_part2))
			return;

		psk_kex_recv_initiator_msg_part2(net, peer, (struct pex_psk_kex_initiator_msg_part2 *)data);
		break;
	case PEX_MSG_PSK_KEX_RESPONDER_MSG_PART1:
	case PEX_MSG_PSK_KEX_RESPONDER_MSG_PART2:
		if (len < sizeof(struct pex_psk_kex_responder_msg))
			return;

		psk_kex_recv_responder_msg(net, peer, opcode, (struct pex_psk_kex_responder_msg *)data);
		break;
	default: return;
	}
}

void gen_kex_hash(void)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, KEX_LABEL, sizeof(KEX_LABEL) - 1);
	sha512_final(&s, kex_hash);
}

void init_psk_kex_ctx(struct network *net, struct network_peer *peer)
{
	memset(&peer->kex_ctx, 0, sizeof(peer->kex_ctx));

	peer->kex_ctx.role = psk_kex_determine_role(net, peer);
	peer->kex_ctx.state = KEX_STATE_IDLE;
}
