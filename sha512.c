/*
 * Copyright (C) 2015-2024 Felix Fietkau <nbd@nbd.name>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* SHA512
 * Daniel Beer <dlbeer@gmail.com>, 22 Apr 2014
 *
 * This file is in the public domain.
 */

#include "sha512.h"

static const uint64_t sha512_initial_state[8] = {
	0x6a09e667f3bcc908LL, 0xbb67ae8584caa73bLL,
	0x3c6ef372fe94f82bLL, 0xa54ff53a5f1d36f1LL,
	0x510e527fade682d1LL, 0x9b05688c2b3e6c1fLL,
	0x1f83d9abfb41bd6bLL, 0x5be0cd19137e2179LL,
};

static const uint64_t round_k[80] = {
	0x428a2f98d728ae22LL, 0x7137449123ef65cdLL,
	0xb5c0fbcfec4d3b2fLL, 0xe9b5dba58189dbbcLL,
	0x3956c25bf348b538LL, 0x59f111f1b605d019LL,
	0x923f82a4af194f9bLL, 0xab1c5ed5da6d8118LL,
	0xd807aa98a3030242LL, 0x12835b0145706fbeLL,
	0x243185be4ee4b28cLL, 0x550c7dc3d5ffb4e2LL,
	0x72be5d74f27b896fLL, 0x80deb1fe3b1696b1LL,
	0x9bdc06a725c71235LL, 0xc19bf174cf692694LL,
	0xe49b69c19ef14ad2LL, 0xefbe4786384f25e3LL,
	0x0fc19dc68b8cd5b5LL, 0x240ca1cc77ac9c65LL,
	0x2de92c6f592b0275LL, 0x4a7484aa6ea6e483LL,
	0x5cb0a9dcbd41fbd4LL, 0x76f988da831153b5LL,
	0x983e5152ee66dfabLL, 0xa831c66d2db43210LL,
	0xb00327c898fb213fLL, 0xbf597fc7beef0ee4LL,
	0xc6e00bf33da88fc2LL, 0xd5a79147930aa725LL,
	0x06ca6351e003826fLL, 0x142929670a0e6e70LL,
	0x27b70a8546d22ffcLL, 0x2e1b21385c26c926LL,
	0x4d2c6dfc5ac42aedLL, 0x53380d139d95b3dfLL,
	0x650a73548baf63deLL, 0x766a0abb3c77b2a8LL,
	0x81c2c92e47edaee6LL, 0x92722c851482353bLL,
	0xa2bfe8a14cf10364LL, 0xa81a664bbc423001LL,
	0xc24b8b70d0f89791LL, 0xc76c51a30654be30LL,
	0xd192e819d6ef5218LL, 0xd69906245565a910LL,
	0xf40e35855771202aLL, 0x106aa07032bbd1b8LL,
	0x19a4c116b8d2d0c8LL, 0x1e376c085141ab53LL,
	0x2748774cdf8eeb99LL, 0x34b0bcb5e19b48a8LL,
	0x391c0cb3c5c95a63LL, 0x4ed8aa4ae3418acbLL,
	0x5b9cca4f7763e373LL, 0x682e6ff3d6b2b8a3LL,
	0x748f82ee5defb2fcLL, 0x78a5636f43172f60LL,
	0x84c87814a1f0ab72LL, 0x8cc702081a6439ecLL,
	0x90befffa23631e28LL, 0xa4506cebde82bde9LL,
	0xbef9a3f7b2c67915LL, 0xc67178f2e372532bLL,
	0xca273eceea26619cLL, 0xd186b8c721c0c207LL,
	0xeada7dd6cde0eb1eLL, 0xf57d4f7fee6ed178LL,
	0x06f067aa72176fbaLL, 0x0a637dc5a2c898a6LL,
	0x113f9804bef90daeLL, 0x1b710b35131c471bLL,
	0x28db77f523047d84LL, 0x32caab7b40c72493LL,
	0x3c9ebe0a15c9bebcLL, 0x431d67c49c100d4cLL,
	0x4cc5d4becb3e42b6LL, 0x597f299cfc657e2aLL,
	0x5fcb6fab3ad6faecLL, 0x6c44198c4a475817LL,
};

static inline uint64_t load64(const uint8_t *x)
{
	uint64_t r;

	r = *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);
	r = (r << 8) | *(x++);

	return r;
}

static inline void store64(uint8_t *x, uint64_t v)
{
	x += 7;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
	v >>= 8;
	*(x--) = v;
}

static inline uint64_t rot64(uint64_t x, int bits)
{
	return (x >> bits) | (x << (64 - bits));
}

static void
sha512_block(struct sha512_state *s, const uint8_t *blk)
{
	uint64_t w[16];
	uint64_t a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = load64(blk);
		blk += 8;
	}

	/* Load state */
	a = s->h[0];
	b = s->h[1];
	c = s->h[2];
	d = s->h[3];
	e = s->h[4];
	f = s->h[5];
	g = s->h[6];
	h = s->h[7];

	for (i = 0; i < 80; i++) {
		/* Compute value of w[i + 16]. w[wrap(i)] is currently w[i] */
		const uint64_t wi = w[i & 15];
		const uint64_t wi15 = w[(i + 1) & 15];
		const uint64_t wi2 = w[(i + 14) & 15];
		const uint64_t wi7 = w[(i + 9) & 15];
		const uint64_t s0 =
			rot64(wi15, 1) ^ rot64(wi15, 8) ^ (wi15 >> 7);
		const uint64_t s1 =
			rot64(wi2, 19) ^ rot64(wi2, 61) ^ (wi2 >> 6);

		/* Round calculations */
		const uint64_t S0 = rot64(a, 28) ^ rot64(a, 34) ^ rot64(a, 39);
		const uint64_t S1 = rot64(e, 14) ^ rot64(e, 18) ^ rot64(e, 41);
		const uint64_t ch = (e & f) ^ ((~e) & g);
		const uint64_t temp1 = h + S1 + ch + round_k[i] + wi;
		const uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
		const uint64_t temp2 = S0 + maj;

		/* Update round state */
		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

		/* w[wrap(i)] becomes w[i + 16] */
		w[i & 15] = wi + s0 + wi7 + s1;
	}

	/* Store state */
	s->h[0] += a;
	s->h[1] += b;
	s->h[2] += c;
	s->h[3] += d;
	s->h[4] += e;
	s->h[5] += f;
	s->h[6] += g;
	s->h[7] += h;
}

void sha512_init(struct sha512_state *s)
{
	memcpy(s->h, &sha512_initial_state, sizeof(s->h));
	s->len = 0;
}

void sha512_add(struct sha512_state *s, const void *data, size_t len)
{
	unsigned int partial = s->len & (SHA512_BLOCK_SIZE - 1);

	if (partial) {
		unsigned int cur = SHA512_BLOCK_SIZE - partial;

		if (cur > len)
			cur = len;

		memcpy(&s->partial[partial], data, cur);

		s->len += cur;
		data += cur;
		len -= cur;

		partial = s->len & (SHA512_BLOCK_SIZE - 1);
		if (!partial)
			sha512_block(s, s->partial);
	}

	while (len >= SHA512_BLOCK_SIZE) {
		sha512_block(s, data);

		s->len += SHA512_BLOCK_SIZE;
		data += SHA512_BLOCK_SIZE;
		len -= SHA512_BLOCK_SIZE;
	}

	if (!len)
		return;

	memcpy(s->partial, data, len);
	s->len += len;
}

void sha512_final(struct sha512_state *s, uint8_t *hash)
{
	size_t last_size = s->len & (SHA512_BLOCK_SIZE - 1);
	unsigned int len = SHA512_HASH_SIZE;
	int i = 0;

	s->partial[last_size++] = 0x80;
	if (last_size < SHA512_BLOCK_SIZE)
		memset(&s->partial[last_size], 0,
		       SHA512_BLOCK_SIZE - last_size);

	if (last_size > (SHA512_BLOCK_SIZE - 16)) {
		sha512_block(s, s->partial);
		memset(s->partial, 0, sizeof(s->partial));
	}

	/* Note: we assume total_size fits in 61 bits */
	store64(s->partial + SHA512_BLOCK_SIZE - 8, s->len << 3);
	sha512_block(s, s->partial);

	/* Read out whole words */
	while (len >= 8) {
		store64(hash, s->h[i++]);
		hash += 8;
		len -= 8;
	}

	/* Read out bytes */
	if (len) {
		uint8_t tmp[8];

		store64(tmp, s->h[i]);
		memcpy(hash, tmp, len);
	}
}

void hmac_sha512(void *dest, const void *key, size_t key_len,
		 const void *data, size_t data_len)
{
	uint8_t k_pad[2 * SHA512_HASH_SIZE] = {};
	struct sha512_state s;

	if (key_len > 128) {
		sha512_init(&s);
		sha512_add(&s, key, key_len);
		sha512_final(&s, k_pad);
	} else {
		memcpy(k_pad, key, key_len);
	}

	for (size_t i = 0; i < sizeof(k_pad); i++)
		k_pad[i] ^= 0x36;

	sha512_init(&s);
	sha512_add(&s, k_pad, sizeof(k_pad));
	sha512_add(&s, data, data_len);
	sha512_final(&s, dest);

	for (size_t i = 0; i < sizeof(k_pad); i++)
		k_pad[i] ^= 0x36 ^ 0x5c;

	sha512_init(&s);
	sha512_add(&s, k_pad, sizeof(k_pad));
	sha512_add(&s, dest, SHA512_HASH_SIZE);
	sha512_final(&s, dest);
}
