
#include "chacha20.h"
#include "curve25519.h"
#include "host.h"
#include "network.h"
#include "pex-msg.h"
#include "psk-kex.h"
#include "random.h"
#include "sha512.h"
#include "siphash.h"
#include "sntrup761.h"
#include <climits>
#include <ctime>
#include <stdbool.h>

#define KEX_LABEL				"WG PQ PSK sntrup761"
#define MAC_LEN					8
#define HANDSHAKE_INTERVAL 		120

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
psk_kex_needs_handshake(struct network_peer *peer)
{
	time_t now = time(NULL);
	uint64_t last = peer->state.last_psk_handshake;

	return last == 0 || now - last > HANDSHAKE_INTERVAL;
}

/*
 * Process should be:
 * - we periodically check if we need a handshake
 * - we send a status request to the peer if we need one
 * - we receive a status response from the peer
 * - this tells us status of peer's handshake and whether it thinks it needs a handshake or not
 * - both peer now know timestamp of last handshake of each other (may be 0; error-prone if clocks not in sync)
 * - if both think they don't need a handshake, skip this
 * - if at least one thinks they need a handshake, do a handshake no matter what the other one thinks. this is safer
 * - both peers can now determine independently of each other which role they have
 * - Initiator will init the handshake, Responder will accept the handshake then
 */


static void
psk_kex_request_status(struct network *net, struct network_peer *peer)
{
	struct pex_psk_kex_status *resp;
	bool we_need_handshake = psk_kex_needs_handshake(peer);

	if (peer->kex_ctx.state != KEX_STATE_IDLE)
		return;

	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_STATUS_REQUEST, true);
	resp = pex_msg_append(sizeof(struct pex_psk_kex_status));
	resp->last_handshake_time = peer->state.last_psk_handshake;
	resp->need_handshake = we_need_handshake;

	pex_msg_send_ext(net, peer, /* address outside of tunnel */ addr);

	peer->kex_ctx.state = KEX_STATE_WAITING_FOR_STATUS_RESPONSE;
}

static void
psk_kex_start_key_exchange(struct network *net, struct network_peer *peer)
{
	struct pex_psk_kex_initiator_msg *msg;
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	if (peer->kex_ctx.role != PSK_KEX_ROLE_INITIATOR)
		return;

	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_INITIATOR_MSG, true);
	msg = pex_msg_append(sizeof(struct pex_psk_kex_initiator_msg));

	/* Generate ephemeral keypair */
	sntrup761_keypair(ctx->e_pub, ctx->e_sec);

	/* Generate k1 and encapsulate it with peer's public key */
	sntrup761_enc(msg->c1, ctx->k1, peer->pqc_pub);
	psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));

	randombytes(&msg->nonce, sizeof(msg->nonce)); /* Generate a random nonce */
	memcpy(&msg->e_pub_enc, ctx->e_pub, sizeof(ctx->e_pub)); /* Copy the ephemeral public key to buf */
	psk_kex_encrypt(msg->e_pub_enc, sizeof(msg->e_pub_enc), msg->e_pub_mac, msg->nonce, key); /* Encrypt + MAC the ephemeral public key */

	/* Send stuff to peer for stage 2 */
	pex_msg_send_ext(net, peer, /* address outside of tunnel */ addr);

	peer->kex_ctx.state = KEX_STATE_WAITING_FOR_RESPONDER;
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
}

static void
psk_kex_recv_status_msg(struct network *net, struct network_peer *peer, struct pex_psk_kex_status *data,
						enum pex_opcode opcode)
{
	struct pex_psk_kex_status *resp;
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	bool we_need_handshake, peer_needs_handshake;

	switch (opcode) {
	case PEX_MSG_PSK_KEX_STATUS_REQUEST:
		/* if we're initiator, sent a request before and now receive another one,
		 * just drop that. Responder has to respond to our request. */
		if (ctx->state == KEX_STATE_WAITING_FOR_STATUS_RESPONSE && ctx->role == PSK_KEX_ROLE_INITIATOR)
			return;
		break;
	case PEX_MSG_PSK_KEX_STATUS_RESPONSE:
		/* Don't accept a response coming out of nowhere */
		if (ctx->state != KEX_STATE_WAITING_FOR_STATUS_RESPONSE)
			return;
		break;
	default: return;
	}

	we_need_handshake = psk_kex_needs_handshake(peer);
	peer_needs_handshake = data->need_handshake;

	if (opcode == PEX_MSG_PSK_KEX_STATUS_REQUEST) {
		pex_msg_init_ext(net, PEX_MSG_PSK_KEX_STATUS_RESPONSE, true);
		resp = pex_msg_append(sizeof(struct pex_psk_kex_status));
		resp->last_handshake_time = peer->state.last_psk_handshake;
		resp->need_handshake = we_need_handshake;

		pex_msg_send_ext(net, peer, /* address outside of tunnel */ addr);
	}

	/* in case no one needs a handshake, don't do anything */
	if (!we_need_handshake && !peer_needs_handshake)
		return;
	/* otherwise, always do a handshake */

	/* designated initiator has to initiate key exchange */
	if (ctx->role == PSK_KEX_ROLE_RESPONDER)
		return;

	/* do we need a delay here? we just sent status response to peer */
	psk_kex_start_key_exchange(net, peer);
	return;
}

static void
psk_kex_recv_initiator_msg(struct network *net, struct network_peer *peer,
						   struct pex_psk_kex_initiator_msg *data)
{
	struct pex_psk_kex_responder_msg *resp;
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	if (peer->kex_ctx.role != PSK_KEX_ROLE_RESPONDER)
		return;

	/* Decrypting part */
	sntrup761_dec(ctx->k1, data->c1, net->config.pqc_sec);
	psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));

	if (!psk_kex_decrypt(data->e_pub_enc, sizeof(data->e_pub_enc), data->e_pub_mac, data->nonce, key))
		return;
	memcpy(ctx->e_pub, data->e_pub_enc, sizeof(ctx->e_pub));

	/* Encrypting part */
	pex_msg_init_ext(net, PEX_MSG_PSK_KEX_RESPONDER_MSG, true);
	pex_msg_append(sizeof(struct pex_psk_kex_responder_msg *));

	randombytes(&resp->nonce, sizeof(resp->nonce));

	/* shared secret 2 */
	sntrup761_enc(resp->c2_enc, ctx->k2, ctx->e_pub);
	psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));
	psk_kex_encrypt(resp->c2_enc, sizeof(resp->c2_enc), resp->c2_mac, resp->nonce, key);

	/* shared secret 3 */
	sntrup761_enc(resp->c3_enc, ctx->k3, peer->pqc_pub);
	psk_kex_keygen(key, ctx->k2, sizeof(ctx->k2));
	psk_kex_encrypt(resp->c3_enc, sizeof(resp->c3_enc), resp->c3_mac, resp->nonce, key);

	pex_msg_send_ext(net, peer, /* address outside of tunnel */ addr);

	psk_kex_finish_key_exchange(net, peer);
}

static void
psk_kex_recv_responder_msg(struct network *net, struct network_peer *peer,
 						   struct pex_psk_kex_responder_msg *data)
{
	struct psk_kex_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	if (ctx->state != KEX_STATE_WAITING_FOR_RESPONDER)
		return;

	psk_kex_keygen(key, ctx->k1, sizeof(ctx->k1));
	if (!psk_kex_decrypt(data->c2_enc, sizeof(data->c2_enc), data->c2_mac, data->nonce, key))
		return;

	sntrup761_dec(ctx->k2, data->c2_enc, ctx->e_sec);

	psk_kex_keygen(key, ctx->k2, sizeof(ctx->k2));
	if (!psk_kex_decrypt(data->c3_enc, sizeof(data->c3_enc), data->c3_mac, data->nonce, key))
		return;

	sntrup761_dec(ctx->k3, data->c3_enc, net->config.pqc_sec);

	psk_kex_finish_key_exchange(net, peer);
}

void psk_kex_recv_msg(struct network *net, struct network_peer *peer, enum pex_opcode opcode, const void *data, size_t len)
{
	if (peer->kex_ctx.role == PSK_KEX_ROLE_NONE)
		return;

	switch (opcode) {
	case PEX_MSG_PSK_KEX_STATUS_REQUEST:
	case PEX_MSG_PSK_KEX_STATUS_RESPONSE:
		if (len < sizeof(struct pex_psk_kex_status))
			return;

		psk_kex_recv_status_msg(net, peer, (struct pex_psk_kex_status *)data, opcode);
		return;
	case PEX_MSG_PSK_KEX_INITIATOR_MSG:
		if (len < sizeof(struct pex_psk_kex_initiator_msg))
			return;

		psk_kex_recv_initiator_msg(net, peer, (struct pex_psk_kex_initiator_msg *)data);
		break;
	case PEX_MSG_PSK_KEX_RESPONDER_MSG:
		if (len < sizeof(struct pex_psk_kex_responder_msg))
			return;

		psk_kex_recv_responder_msg(net, peer, (struct pex_psk_kex_responder_msg *)data);
		break;
	default: return;
	}

	// TODO: update network to use new psk
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
