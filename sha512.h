/*
 * Copyright (C) 2015 Felix Fietkau <nbd@openwrt.org>
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

#ifndef SHA512_H_
#define SHA512_H_

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Feed a full block in */
#define SHA512_BLOCK_SIZE	128

/* SHA512 state. State is updated as data is fed in, and then the final
 * hash can be read out in slices.
 *
 * Data is fed in as a sequence of full blocks terminated by a single
 * partial block.
 */
struct sha512_state {
	uint64_t h[8];
	uint8_t partial[SHA512_BLOCK_SIZE];
	size_t len;
};

/* Set up a new context */
void sha512_init(struct sha512_state *s);

void sha512_add(struct sha512_state *s, const void *data, size_t len);

/* Fetch a slice of the hash result. */
#define SHA512_HASH_SIZE	64

void sha512_final(struct sha512_state *s, uint8_t *hash);

static inline void *
sha512_final_get(struct sha512_state *s)
{
	sha512_final(s, s->partial);
	return s->partial;
}

#endif
