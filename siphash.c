/* Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 */

#include <libubox/utils.h>
#include "siphash.h"

static inline uint64_t rol64(uint64_t word, unsigned int shift)
{
	return (word << (shift & 63)) | (word >> ((-shift) & 63));
}


#define SIPROUND \
	do { \
	v0 += v1; v1 = rol64(v1, 13); v1 ^= v0; v0 = rol64(v0, 32); \
	v2 += v3; v3 = rol64(v3, 16); v3 ^= v2; \
	v0 += v3; v3 = rol64(v3, 21); v3 ^= v0; \
	v2 += v1; v1 = rol64(v1, 17); v1 ^= v2; v2 = rol64(v2, 32); \
	} while (0)

#define PREAMBLE(len) \
	uint64_t v0 = 0x736f6d6570736575ULL; \
	uint64_t v1 = 0x646f72616e646f6dULL; \
	uint64_t v2 = 0x6c7967656e657261ULL; \
	uint64_t v3 = 0x7465646279746573ULL; \
	uint64_t b = ((uint64_t)(len)) << 56; \
	v3 ^= key->key[1]; \
	v2 ^= key->key[0]; \
	v1 ^= key->key[1]; \
	v0 ^= key->key[0];

#define POSTAMBLE \
	v3 ^= b; \
	SIPROUND; \
	SIPROUND; \
	v0 ^= b; \
	v2 ^= 0xff; \
	SIPROUND; \
	SIPROUND; \
	SIPROUND; \
	SIPROUND; \
	return (v0 ^ v1) ^ (v2 ^ v3);


uint64_t siphash(const void *data, size_t len, const siphash_key_t *key)
{
	const uint8_t *end = data + len - (len % sizeof(uint64_t));
	const uint8_t left = len & (sizeof(uint64_t) - 1);
	uint64_t m;
	PREAMBLE(len)
	for (; data != end; data += sizeof(uint64_t)) {
		m = get_unaligned_le64(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}
	switch (left) {
	case 7: b |= ((uint64_t)end[6]) << 48; fallthrough;
	case 6: b |= ((uint64_t)end[5]) << 40; fallthrough;
	case 5: b |= ((uint64_t)end[4]) << 32; fallthrough;
	case 4: b |= get_unaligned_le32(end); break;
	case 3: b |= ((uint64_t)end[2]) << 16; fallthrough;
	case 2: b |= get_unaligned_le16(end); break;
	case 1: b |= end[0];
	}
	POSTAMBLE
}
