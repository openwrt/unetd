// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Jonas Jelonek <jelonek.jonas@gmail.com>
 * Copyright (C) 2026 Felix Fietkau <nbd@nbd.name>
 */
#include <time.h>
#include "unetd.h"
#include "curve25519.h"
#include "pex-pqc.h"
#include "random.h"
#include "sha512.h"

#define KEX_LABEL			"WG PQ PSK sntrup761"
#define PEX_PQC_HANDSHAKE_INTERVAL	3600
#define PEX_PQC_MAX_RETRANSMIT		5
#define PEX_PQC_REJECT_MIN_INTERVAL	1

static uint8_t kex_hash[SHA512_HASH_SIZE];

enum pex_pqc_domain {
	PEX_PQC_DOMAIN_C1,
	PEX_PQC_DOMAIN_E_PUB,
	PEX_PQC_DOMAIN_C2,
	PEX_PQC_DOMAIN_C3,
	PEX_PQC_DOMAIN_REJECT,
};


static enum pex_pqc_role
pex_pqc_determine_role(struct network *net, struct network_peer *peer)
{
	int cmp = memcmp(net->config.pubkey, peer->key, CURVE25519_KEY_SIZE);
	if (cmp > 0) {
		return PEX_PQC_ROLE_INITIATOR;
	} else if (cmp < 0) {
		return PEX_PQC_ROLE_RESPONDER;
	} else {
		return PEX_PQC_ROLE_NONE;
	}
}

static void
pex_pqc_keygen(uint8_t *dest, const void *src, size_t len)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, kex_hash, sizeof(kex_hash));
	sha512_add(&s, src, len);
	memcpy(dest, sha512_final_get(&s), CHACHA20_KEY_SIZE);
}

/*
 * Bind the cleartext nonce, a per-message domain and an optional challenge
 * token into the MAC key, so that tampering with the transmitted nonce,
 * reflecting a ciphertext as a different message type, or replaying an M1A
 * against a fresh challenge all invalidate the MAC.
 */
static void
pex_pqc_mac(uint8_t *mac, uint8_t domain, const uint8_t *data, size_t len,
	    const uint8_t *nonce, const uint8_t *key, const uint8_t *token)
{
	uint8_t mac_key[CHACHA20_KEY_SIZE];
	uint8_t hash[SHA512_HASH_SIZE];
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, key, CHACHA20_KEY_SIZE);
	sha512_add(&s, nonce, CHACHA20_NONCE_SIZE);
	sha512_add(&s, &domain, sizeof(domain));
	if (token)
		sha512_add(&s, token, PEX_PQC_CHALLENGE_LEN);
	memcpy(mac_key, sha512_final_get(&s), sizeof(mac_key));

	hmac_sha512(hash, mac_key, sizeof(mac_key), data, len);
	memcpy(mac, hash, PEX_PQC_MAC_LEN);
}

static bool
pex_pqc_mac_equal(const uint8_t *a, const uint8_t *b)
{
	uint8_t diff = 0;

	for (size_t i = 0; i < PEX_PQC_MAC_LEN; i++)
		diff |= a[i] ^ b[i];

	return diff == 0;
}

static void
pex_pqc_encrypt(uint8_t *dest, size_t len, uint8_t *mac, uint8_t domain,
		const uint8_t *nonce, const uint8_t *key, const uint8_t *token)
{
	chacha20_encrypt_msg(dest, len, nonce, key);
	pex_pqc_mac(mac, domain, dest, len, nonce, key, token);
}

static bool
pex_pqc_decrypt(uint8_t *dest, size_t len, const uint8_t *mac, uint8_t domain,
		const uint8_t *nonce, const uint8_t *key, const uint8_t *token)
{
	uint8_t check_mac[PEX_PQC_MAC_LEN];

	pex_pqc_mac(check_mac, domain, dest, len, nonce, key, token);
	if (!pex_pqc_mac_equal(check_mac, mac))
		return false;

	chacha20_encrypt_msg(dest, len, nonce, key);
	return true;
}

static bool
pex_pqc_challenge_pending(struct pex_pqc_ctx *ctx)
{
	uint8_t acc = 0;

	for (size_t i = 0; i < sizeof(ctx->challenge); i++)
		acc |= ctx->challenge[i];

	return acc != 0;
}

static void
pex_pqc_derive_psk(struct pex_pqc_ctx *ctx, uint8_t *psk)
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
pex_pqc_need_handshake(struct network_peer *peer)
{
	time_t now = time(NULL);
	uint64_t last = peer->state.last_psk_handshake;

	return last == 0 || now - last > PEX_PQC_HANDSHAKE_INTERVAL;
}


static void
pex_pqc_msg_send(struct network *net, struct network_peer *peer)
{
	int i, j;

	for (i = 0; i < __ENDPOINT_TYPE_MAX; i++) {
		union network_endpoint *ep = &peer->state.next_endpoint[i];

		if (!ep->sa.sa_family)
			continue;

		for (j = 0; j < i; j++)
			if (!memcmp(ep, &peer->state.next_endpoint[j], sizeof(*ep)))
				break;
		if (j < i)
			continue;

		pex_msg_send_ext(net, peer, &ep->in6);
	}
}

static void
pex_pqc_finish_key_exchange(struct network *net, struct network_peer *peer)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	uint8_t dh_key[CURVE25519_KEY_SIZE];

	pex_pqc_derive_psk(ctx, peer->psk);

	peer->state.last_psk_handshake = time(NULL);
	wg_peer_update(net, peer, WG_PEER_UPDATE);

	if (ctx->role == PEX_PQC_ROLE_RESPONDER) {
		/* keep the response cached so a lost M2 can be retransmitted */
		ctx->state = PEX_PQC_STATE_RESPONDER_DONE;
		return;
	}

	memcpy(dh_key, ctx->dh_key, sizeof(dh_key));
	memset(ctx, 0, sizeof(*ctx));
	ctx->role = pex_pqc_determine_role(net, peer);
	memcpy(ctx->dh_key, dh_key, sizeof(ctx->dh_key));
}

static void
pex_pqc_init_m1(struct network *net, struct network_peer *peer)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	uint8_t k1_key[CHACHA20_KEY_SIZE];

	uint64_t ts = cpu_to_be64((uint64_t)time(NULL));

	/* start on the fast path; a reject switches to a challenge-bound MAC */
	memset(ctx->challenge, 0, sizeof(ctx->challenge));

	sntrup761_keypair(ctx->e_pub, ctx->e_sec);
	sntrup761_enc(ctx->msg_c1, ctx->k1, peer->pqc_pub);
	memcpy(ctx->msg_c1_time, &ts, sizeof(ctx->msg_c1_time));

	randombytes(ctx->msg_c1_nonce, sizeof(ctx->msg_c1_nonce));
	pex_pqc_encrypt(ctx->msg_c1, sizeof(ctx->msg_c1) + sizeof(ctx->msg_c1_time),
			ctx->msg_c1_mac, PEX_PQC_DOMAIN_C1, ctx->msg_c1_nonce,
			ctx->dh_key, NULL);

	pex_pqc_keygen(k1_key, ctx->k1, sizeof(ctx->k1));
	randombytes(ctx->msg_e_pub_nonce, sizeof(ctx->msg_e_pub_nonce));
	memcpy(ctx->msg_e_pub_enc, ctx->e_pub, sizeof(ctx->e_pub));
	pex_pqc_encrypt(ctx->msg_e_pub_enc, sizeof(ctx->msg_e_pub_enc),
			ctx->msg_e_pub_mac, PEX_PQC_DOMAIN_E_PUB, ctx->msg_e_pub_nonce,
			k1_key, NULL);

	ctx->state = PEX_PQC_STATE_WAITING_FOR_M2A;
	ctx->retransmit_count = 0;
}

static void
pex_pqc_send_m1(struct network *net, struct network_peer *peer)
{
	struct pex_pqc_m1a *msg_a;
	struct pex_pqc_m1b *msg_b;
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;

	pex_msg_init_ext(net, PEX_MSG_PQC_M1A, true);
	msg_a = pex_msg_append(sizeof(*msg_a));
	memcpy(msg_a->c1, ctx->msg_c1, sizeof(msg_a->c1));
	memcpy(msg_a->c1_time, ctx->msg_c1_time, sizeof(msg_a->c1_time));
	memcpy(msg_a->c1_mac, ctx->msg_c1_mac, sizeof(msg_a->c1_mac));
	memcpy(msg_a->nonce, ctx->msg_c1_nonce, sizeof(msg_a->nonce));
	pex_pqc_msg_send(net, peer);

	pex_msg_init_ext(net, PEX_MSG_PQC_M1B, true);
	msg_b = pex_msg_append(sizeof(*msg_b));
	memcpy(msg_b->e_pub_enc, ctx->msg_e_pub_enc, sizeof(msg_b->e_pub_enc));
	memcpy(msg_b->e_pub_mac, ctx->msg_e_pub_mac, sizeof(msg_b->e_pub_mac));
	memcpy(msg_b->nonce, ctx->msg_e_pub_nonce, sizeof(msg_b->nonce));
	pex_pqc_msg_send(net, peer);
}

static void
pex_pqc_send_m2(struct network *net, struct network_peer *peer)
{
	struct pex_pqc_m2 *resp;
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;

	pex_msg_init_ext(net, PEX_MSG_PQC_M2A, true);
	resp = pex_msg_append(sizeof(*resp));
	memcpy(resp->c_enc, ctx->resp_c2_enc, sizeof(resp->c_enc));
	memcpy(resp->c_mac, ctx->resp_c2_mac, sizeof(resp->c_mac));
	memcpy(resp->nonce, ctx->resp_nonce, sizeof(resp->nonce));
	pex_pqc_msg_send(net, peer);

	pex_msg_init_ext(net, PEX_MSG_PQC_M2B, true);
	resp = pex_msg_append(sizeof(*resp));
	memcpy(resp->c_enc, ctx->resp_c3_enc, sizeof(resp->c_enc));
	memcpy(resp->c_mac, ctx->resp_c3_mac, sizeof(resp->c_mac));
	memcpy(resp->nonce, ctx->resp_nonce, sizeof(resp->nonce));
	pex_pqc_msg_send(net, peer);
}

/*
 * The initiator's M1A timestamp did not clear the replay high-water mark.
 * Issue (or resend) a fresh random challenge bound to the rejected M1A; only a
 * peer holding dh_key can echo it into a retransmitted M1A, which then lets the
 * responder accept and reset the high-water mark. Rate-limited on a monotonic
 * clock to bound reject churn from replayed M1As.
 */
static void
pex_pqc_send_reject(struct network *net, struct network_peer *peer,
		    const uint8_t *m1a_ref)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	struct pex_pqc_m1_reject *msg;
	uint64_t now = unet_gettime();

	/*
	 * Rate-limit reject generation on a monotonic clock to bound challenge
	 * churn and amplification from replayed M1As.
	 */
	if (ctx->last_reject_time &&
	    now - ctx->last_reject_time < PEX_PQC_REJECT_MIN_INTERVAL)
		return;

	/*
	 * Fresh challenge per handshake attempt (keyed by the M1A nonce), so an
	 * old challenge-bound M1A cannot be replayed to reset the high-water mark;
	 * reuse it across retransmits of the same rejected M1A.
	 */
	if (!pex_pqc_challenge_pending(ctx) ||
	    memcmp(ctx->challenge_ref, m1a_ref, sizeof(ctx->challenge_ref))) {
		randombytes(ctx->challenge, sizeof(ctx->challenge));
		memcpy(ctx->challenge_ref, m1a_ref, sizeof(ctx->challenge_ref));
	}
	ctx->last_reject_time = now;

	pex_msg_init_ext(net, PEX_MSG_PQC_M1_REJECT, true);
	msg = pex_msg_append(sizeof(*msg));
	if (!msg)
		return;

	memcpy(msg->m1a_ref, m1a_ref, sizeof(msg->m1a_ref));
	memcpy(msg->challenge, ctx->challenge, sizeof(msg->challenge));
	pex_pqc_mac(msg->mac, PEX_PQC_DOMAIN_REJECT, msg->challenge,
		    sizeof(msg->challenge), msg->m1a_ref, ctx->dh_key, NULL);
	pex_pqc_msg_send(net, peer);
}

static void
pex_pqc_accept_m1a(struct network *net, struct network_peer *peer,
		   struct pex_pqc_m1a *data, uint64_t ts)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;

	peer->state.last_pqc_init_time = ts;
	sntrup761_dec(ctx->k1, data->c1, net->config.pqc_sec);
	ctx->state = PEX_PQC_STATE_WAITING_FOR_M1B;
}

static void
pex_pqc_recv_m1a(struct network *net, struct network_peer *peer,
				 struct pex_pqc_m1a *data)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	size_t clen = sizeof(data->c1) + sizeof(data->c1_time);
	bool have_challenge = false;
	uint64_t ts;

	if (pex_pqc_decrypt(data->c1, clen, data->c1_mac, PEX_PQC_DOMAIN_C1,
			    data->nonce, ctx->dh_key, NULL)) {
		/* fast-path M1A, MAC not bound to a challenge */
	} else if (pex_pqc_challenge_pending(ctx) &&
		   pex_pqc_decrypt(data->c1, clen, data->c1_mac, PEX_PQC_DOMAIN_C1,
				   data->nonce, ctx->dh_key, ctx->challenge)) {
		have_challenge = true;
	} else {
		return;
	}

	memcpy(&ts, data->c1_time, sizeof(ts));
	ts = be64_to_cpu(ts);

	/*
	 * Retransmission of a completed handshake (fast-path or challenge-bound):
	 * resend the cached response.
	 */
	if (ts == peer->state.last_pqc_init_time &&
	    ctx->state == PEX_PQC_STATE_RESPONDER_DONE) {
		pex_pqc_send_m2(net, peer);
		return;
	}

	/*
	 * A valid challenge proves freshness, so it may reset the high-water mark
	 * downward (clock regression recovery); the pending challenge is kept so a
	 * lost M2 can still be recovered. A newer timestamp starts a new handshake;
	 * an equal one re-runs M1B idempotently after an M1B loss or a responder-
	 * side timeout. A fast-path accept ends the challenge, restoring the baseline.
	 */
	if (have_challenge || ts >= peer->state.last_pqc_init_time) {
		if (!have_challenge)
			memset(ctx->challenge, 0, sizeof(ctx->challenge));
		pex_pqc_accept_m1a(net, peer, data, ts);
		return;
	}

	/* ts < last: replay or clock regression -> challenge the initiator */
	pex_pqc_send_reject(net, peer, data->nonce);
}

static void
pex_pqc_recv_m1b(struct network *net, struct network_peer *peer,
				 struct pex_pqc_m1b *data)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	if (ctx->state != PEX_PQC_STATE_WAITING_FOR_M1B)
		return;

	pex_pqc_keygen(key, ctx->k1, sizeof(ctx->k1));
	if (!pex_pqc_decrypt(data->e_pub_enc, sizeof(data->e_pub_enc),
			     data->e_pub_mac, PEX_PQC_DOMAIN_E_PUB, data->nonce, key, NULL))
		return;
	memcpy(ctx->e_pub, data->e_pub_enc, sizeof(ctx->e_pub));

	randombytes(ctx->resp_nonce, sizeof(ctx->resp_nonce));

	sntrup761_enc(ctx->resp_c2_enc, ctx->k2, ctx->e_pub);
	pex_pqc_encrypt(ctx->resp_c2_enc, sizeof(ctx->resp_c2_enc),
			ctx->resp_c2_mac, PEX_PQC_DOMAIN_C2, ctx->resp_nonce, key, NULL);

	sntrup761_enc(ctx->resp_c3_enc, ctx->k3, peer->pqc_pub);
	pex_pqc_keygen(key, ctx->k2, sizeof(ctx->k2));
	pex_pqc_encrypt(ctx->resp_c3_enc, sizeof(ctx->resp_c3_enc),
			ctx->resp_c3_mac, PEX_PQC_DOMAIN_C3, ctx->resp_nonce, key, NULL);

	pex_pqc_send_m2(net, peer);
	pex_pqc_finish_key_exchange(net, peer);
}

static void
pex_pqc_recv_m2a(struct network *net, struct network_peer *peer,
		 struct pex_pqc_m2 *data)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	if (ctx->state != PEX_PQC_STATE_WAITING_FOR_M2A)
		return;

	pex_pqc_keygen(key, ctx->k1, sizeof(ctx->k1));
	if (!pex_pqc_decrypt(data->c_enc, sizeof(data->c_enc),
			     data->c_mac, PEX_PQC_DOMAIN_C2, data->nonce, key, NULL))
		return;

	sntrup761_dec(ctx->k2, data->c_enc, ctx->e_sec);
	ctx->state = PEX_PQC_STATE_WAITING_FOR_M2B;
	ctx->retransmit_count = 0;
}

static void
pex_pqc_recv_m2b(struct network *net, struct network_peer *peer,
		 struct pex_pqc_m2 *data)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	uint8_t key[CHACHA20_KEY_SIZE];

	if (ctx->state != PEX_PQC_STATE_WAITING_FOR_M2B)
		return;

	pex_pqc_keygen(key, ctx->k2, sizeof(ctx->k2));
	if (!pex_pqc_decrypt(data->c_enc, sizeof(data->c_enc),
			     data->c_mac, PEX_PQC_DOMAIN_C3, data->nonce, key, NULL))
		return;

	sntrup761_dec(ctx->k3, data->c_enc, net->config.pqc_sec);
	pex_pqc_finish_key_exchange(net, peer);
}

static void
pex_pqc_recv_reject(struct network *net, struct network_peer *peer,
		    struct pex_pqc_m1_reject *data)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;
	uint8_t check_mac[PEX_PQC_MAC_LEN];

	if (ctx->state != PEX_PQC_STATE_WAITING_FOR_M2A)
		return;

	/* only a reject for the M1A we are currently waiting on */
	if (memcmp(data->m1a_ref, ctx->msg_c1_nonce, sizeof(data->m1a_ref)) != 0)
		return;

	pex_pqc_mac(check_mac, PEX_PQC_DOMAIN_REJECT, data->challenge,
		    sizeof(data->challenge), data->m1a_ref, ctx->dh_key, NULL);
	if (!pex_pqc_mac_equal(check_mac, data->mac))
		return;

	memcpy(ctx->challenge, data->challenge, sizeof(ctx->challenge));
	pex_pqc_mac(ctx->msg_c1_mac, PEX_PQC_DOMAIN_C1, ctx->msg_c1,
		    sizeof(ctx->msg_c1) + sizeof(ctx->msg_c1_time),
		    ctx->msg_c1_nonce, ctx->dh_key, ctx->challenge);
	ctx->retransmit_count = 0;
	pex_pqc_send_m1(net, peer);
}

void
pex_pqc_recv(struct network *net, struct network_peer *peer,
		 enum pex_opcode opcode, void *data, size_t len)
{
	switch (opcode) {
	case PEX_MSG_PQC_M1A:
	case PEX_MSG_PQC_M1B:
		if (peer->kex_ctx.role != PEX_PQC_ROLE_RESPONDER)
			return;
		break;
	case PEX_MSG_PQC_M2A:
	case PEX_MSG_PQC_M2B:
	case PEX_MSG_PQC_M1_REJECT:
		if (peer->kex_ctx.role != PEX_PQC_ROLE_INITIATOR)
			return;
		break;
	default:
		return;
	}

	switch (opcode) {
	case PEX_MSG_PQC_M1A:
		if (len < sizeof(struct pex_pqc_m1a))
			return;

		pex_pqc_recv_m1a(net, peer, (struct pex_pqc_m1a *)data);
		break;
	case PEX_MSG_PQC_M1B:
		if (len < sizeof(struct pex_pqc_m1b))
			return;

		pex_pqc_recv_m1b(net, peer, (struct pex_pqc_m1b *)data);
		break;
	case PEX_MSG_PQC_M2A:
		if (len < sizeof(struct pex_pqc_m2))
			return;

		pex_pqc_recv_m2a(net, peer, (struct pex_pqc_m2 *)data);
		break;
	case PEX_MSG_PQC_M2B:
		if (len < sizeof(struct pex_pqc_m2))
			return;

		pex_pqc_recv_m2b(net, peer, (struct pex_pqc_m2 *)data);
		break;
	case PEX_MSG_PQC_M1_REJECT:
		if (len < sizeof(struct pex_pqc_m1_reject))
			return;

		pex_pqc_recv_reject(net, peer, (struct pex_pqc_m1_reject *)data);
		break;
	default:
		return;
	}
}

void
pex_pqc_poll(struct network *net, struct network_peer *peer)
{
	struct pex_pqc_ctx *ctx = &peer->kex_ctx;

	switch (ctx->state) {
	case PEX_PQC_STATE_IDLE:
		if (ctx->role != PEX_PQC_ROLE_INITIATOR ||
		    !pex_pqc_need_handshake(peer))
			break;

		pex_pqc_init_m1(net, peer);
		pex_pqc_send_m1(net, peer);
		break;
	case PEX_PQC_STATE_WAITING_FOR_M2A:
	case PEX_PQC_STATE_WAITING_FOR_M2B:
		if (++ctx->retransmit_count > PEX_PQC_MAX_RETRANSMIT) {
			ctx->state = PEX_PQC_STATE_IDLE;
			ctx->retransmit_count = 0;
			break;
		}
		pex_pqc_send_m1(net, peer);
		break;
	case PEX_PQC_STATE_WAITING_FOR_M1B:
		if (++ctx->retransmit_count > PEX_PQC_MAX_RETRANSMIT) {
			ctx->state = PEX_PQC_STATE_IDLE;
			ctx->retransmit_count = 0;
		}
		break;
	case PEX_PQC_STATE_RESPONDER_DONE:
		break;
	}
}

void pex_pqc_hash_init(void)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, KEX_LABEL, sizeof(KEX_LABEL) - 1);
	sha512_final(&s, kex_hash);
}

void pex_pqc_ctx_init(struct network *net, struct network_peer *peer)
{
	memset(&peer->kex_ctx, 0, sizeof(peer->kex_ctx));

	peer->kex_ctx.role = pex_pqc_determine_role(net, peer);
	peer->kex_ctx.state = PEX_PQC_STATE_IDLE;
	curve25519(peer->kex_ctx.dh_key, net->config.key, peer->key);
	pex_pqc_keygen(peer->kex_ctx.dh_key, peer->kex_ctx.dh_key,
		       sizeof(peer->kex_ctx.dh_key));
}
