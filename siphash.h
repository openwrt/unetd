/* Copyright (C) 2016 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This file is provided under a dual BSD/GPLv2 license.
 *
 * SipHash: a fast short-input PRF
 * https://131002.net/siphash/
 *
 * This implementation is specifically for SipHash2-4 for a secure PRF
 * and HalfSipHash1-3/SipHash1-3 for an insecure PRF only suitable for
 * hashtables.
 */

#ifndef _LINUX_SIPHASH_H
#define _LINUX_SIPHASH_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libubox/utils.h>

#define SIPHASH_ALIGNMENT __alignof__(uint64_t)
typedef struct {
	uint64_t key[2];
} siphash_key_t;

static inline uint16_t get_unaligned_le16(const uint8_t *p)
{
	return p[0] | p[1] << 8;
}

static inline uint32_t get_unaligned_le32(const uint8_t *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24;
}

static inline uint64_t get_unaligned_le64(const uint8_t *p)
{
	return (uint64_t)get_unaligned_le32(p + 4) << 32 |
	       get_unaligned_le32(p);
}

static inline bool siphash_key_is_zero(const siphash_key_t *key)
{
	return !(key->key[0] | key->key[1]);
}

uint64_t siphash(const void *data, size_t len, const siphash_key_t *key);

static inline void siphash_to_le64(void *dest, const void *data, size_t len,
				   const siphash_key_t *key)
{
	uint64_t hash = siphash(data, len, key);

	*(uint64_t *)dest = cpu_to_le64(hash);
}

#endif /* _LINUX_SIPHASH_H */
