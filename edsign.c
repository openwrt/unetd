/* Edwards curve signature system
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */

#include "ed25519.h"
#include "sha512.h"
#include "fprime.h"
#include "edsign.h"

#define EXPANDED_SIZE		64

static const uint8_t ed25519_order[FPRIME_SIZE] = {
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

static void expand_key(uint8_t *expanded, const uint8_t *secret)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, secret, EDSIGN_SECRET_KEY_SIZE);
	sha512_final(&s, expanded);

	ed25519_prepare(expanded);
}

static uint8_t upp(struct ed25519_pt *p, const uint8_t *packed)
{
	uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];
	uint8_t ok = ed25519_try_unpack(x, y, packed);

	ed25519_project(p, x, y);
	return ok;
}

static void pp(uint8_t *packed, const struct ed25519_pt *p)
{
	uint8_t x[F25519_SIZE];
	uint8_t y[F25519_SIZE];

	ed25519_unproject(x, y, p);
	ed25519_pack(packed, x, y);
}

static void sm_pack(uint8_t *r, const uint8_t *k)
{
	struct ed25519_pt p;

	ed25519_smult(&p, &ed25519_base, k);
	pp(r, &p);
}

void edsign_sec_to_pub(void *pub, const void *secret)
{
	uint8_t expanded[EXPANDED_SIZE];

	expand_key(expanded, secret);
	sm_pack(pub, expanded);
}

static void save_hash(struct sha512_state *s, uint8_t *out)
{
	void *hash;

	hash = sha512_final_get(s);
	fprime_from_bytes(out, hash, SHA512_HASH_SIZE, ed25519_order);
}

static void generate_k(uint8_t *k, const uint8_t *kgen_key,
		       const uint8_t *message, size_t len)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, kgen_key, 32);
	sha512_add(&s, message, len);
	save_hash(&s, k);
}

static void hash_message(uint8_t *z, const uint8_t *r, const uint8_t *a,
			 const uint8_t *m, size_t len)
{
	struct sha512_state s;

	sha512_init(&s);
	sha512_add(&s, r, 32);
	sha512_add(&s, a, 32);
	sha512_add(&s, m, len);
	save_hash(&s, z);
}

void edsign_sign(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len)
{
	uint8_t expanded[EXPANDED_SIZE];
	uint8_t e[FPRIME_SIZE];
	uint8_t s[FPRIME_SIZE];
	uint8_t k[FPRIME_SIZE];
	uint8_t z[FPRIME_SIZE];

	expand_key(expanded, secret);

	/* Generate k and R = kB */
	generate_k(k, expanded + 32, message, len);
	sm_pack(signature, k);

	/* Compute z = H(R, A, M) */
	hash_message(z, signature, pub, message, len);

	/* Obtain e */
	fprime_from_bytes(e, expanded, 32, ed25519_order);

	/* Compute s = ze + k */
	fprime_mul(s, z, e, ed25519_order);
	fprime_add(s, k, ed25519_order);
	memcpy(signature + 32, s, 32);
}

void edsign_verify_init(struct edsign_verify_state *st, const void *sig,
			const void *pub)
{
	sha512_init(&st->sha);
	sha512_add(&st->sha, sig, 32);
	sha512_add(&st->sha, pub, 32);
}

bool edsign_verify(struct edsign_verify_state *st, const void *sig, const void *pub)
{
	struct ed25519_pt p;
	struct ed25519_pt q;
	uint8_t lhs[F25519_SIZE];
	uint8_t rhs[F25519_SIZE];
	uint8_t z[FPRIME_SIZE];
	uint8_t ok = 1;

	/* Compute z = H(R, A, M) */
	save_hash(&st->sha, z);

	/* sB = (ze + k)B = ... */
	sm_pack(lhs, sig + 32);

	/* ... = zA + R */
	ok &= upp(&p, pub);
	ed25519_smult(&p, &p, z);
	ok &= upp(&q, sig);
	ed25519_add(&p, &p, &q);
	pp(rhs, &p);

	/* Equal? */
	return ok & f25519_eq(lhs, rhs);
}
