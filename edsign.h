/* Edwards curve signature system
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */

#ifndef EDSIGN_H_
#define EDSIGN_H_

#include <stdint.h>
#include <stdbool.h>
#include "sha512.h"

/* This is the Ed25519 signature system, as described in:
 *
 *     Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, Bo-Yin
 *     Yang. High-speed high-security signatures. Journal of Cryptographic
 *     Engineering 2 (2012), 77–89. Document ID:
 *     a1a62a2f76d23f65d622484ddd09caf8. URL:
 *     http://cr.yp.to/papers.html#ed25519. Date: 2011.09.26. 
 *
 * The format and calculation of signatures is compatible with the
 * Ed25519 implementation in SUPERCOP. Note, however, that our secret
 * keys are half the size: we don't store a copy of the public key in
 * the secret key (we generate it on demand).
 */

/* Any string of 32 random bytes is a valid secret key. There is no
 * clamping of bits, because we don't use the key directly as an
 * exponent (the exponent is derived from part of a key expansion).
 */
#define EDSIGN_SECRET_KEY_SIZE		32

/* Given a secret key, produce the public key (a packed Edwards-curve
 * point).
 */
#define EDSIGN_PUBLIC_KEY_SIZE		32

void edsign_sec_to_pub(void *pub, const void *secret);

/* Produce a signature for a message. */
#define EDSIGN_SIGNATURE_SIZE		64

void edsign_sign(uint8_t *signature, const uint8_t *pub,
		 const uint8_t *secret,
		 const uint8_t *message, size_t len);

struct edsign_verify_state {
	struct sha512_state sha;
};

void edsign_verify_init(struct edsign_verify_state *st, const void *sig,
			const void *pub);

static inline void
edsign_verify_add(struct edsign_verify_state *st, const void *data, int len)
{
	sha512_add(&st->sha, data, len);
}

/* Verify a message signature. Returns non-zero if ok. */
bool edsign_verify(struct edsign_verify_state *st, const void *sig, const void *pub);

#endif
