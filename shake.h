/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_FIPS202_FIPS202_H
#define MLD_FIPS202_FIPS202_H

#include <stddef.h>
#include <stdint.h>

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define MLD_KECCAK_LANES 25
#define SHA3_256_HASHBYTES 32
#define SHA3_512_HASHBYTES 64

#define MLD_KECCAK_LANES 25
#define MLD_KECCAK_WAY 4

typedef struct
{
  uint64_t s[MLD_KECCAK_LANES];
  unsigned int pos;
} keccak_state;

/* Context for non-incremental API */
typedef struct
{
  uint64_t ctx[MLD_KECCAK_LANES * MLD_KECCAK_WAY];
} mld_shake128x4ctx;

typedef struct
{
  uint64_t ctx[MLD_KECCAK_LANES * MLD_KECCAK_WAY];
} mld_shake256x4ctx;

extern const uint64_t KeccakF_RoundConstants[];

void shake128_init(keccak_state *state);
void shake128_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake128_finalize(keccak_state *state);
void shake128_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake128_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);

void shake128_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
void shake128_release(keccak_state *state);

void shake256_init(keccak_state *state);
void shake256_absorb(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_finalize(keccak_state *state);

void shake256_squeeze(uint8_t *out, size_t outlen, keccak_state *state);
void shake256_absorb_once(keccak_state *state, const uint8_t *in, size_t inlen);
void shake256_squeezeblocks(uint8_t *out, size_t nblocks, keccak_state *state);
void shake256_release(keccak_state *state);

void shake128(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);
void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);;

void sha3_256(uint8_t h[SHA3_256_HASHBYTES], const uint8_t *in, size_t inlen);

void sha3_512(uint8_t h[SHA3_512_HASHBYTES], const uint8_t *in, size_t inlen);

void mld_shake128x4_absorb_once(mld_shake128x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen);
void mld_shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mld_shake128x4ctx *state);
void mld_shake128x4_init(mld_shake128x4ctx *state);
void mld_shake128x4_release(mld_shake128x4ctx *state);
void mld_shake256x4_absorb_once(mld_shake256x4ctx *state, const uint8_t *in0,
                                const uint8_t *in1, const uint8_t *in2,
                                const uint8_t *in3, size_t inlen);
void mld_shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
                                  uint8_t *out3, size_t nblocks,
                                  mld_shake256x4ctx *state);
void mld_shake256x4_init(mld_shake256x4ctx *state);
void mld_shake256x4_release(mld_shake256x4ctx *state);

#endif /* !MLD_FIPS202_FIPS202_H */
