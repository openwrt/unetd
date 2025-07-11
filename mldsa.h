/*
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef MLD_API_H
#define MLD_API_H

#include <stddef.h>
#include <stdint.h>

#define MLD_44_PUBLICKEYBYTES 1312
#define MLD_44_SECRETKEYBYTES 2560
#define MLD_44_BYTES 2420

#define MLD_44_ref_PUBLICKEYBYTES MLD_44_PUBLICKEYBYTES
#define MLD_44_ref_SECRETKEYBYTES MLD_44_SECRETKEYBYTES
#define MLD_44_ref_BYTES MLD_44_BYTES

int MLD_44_ref_keypair(uint8_t *pk, uint8_t *sk);
int MLD_44_ref_pubkey(uint8_t *pk, const uint8_t *sk);

int MLD_44_ref_signature(uint8_t *sig, size_t *siglen, const uint8_t *m,
                         size_t mlen, const uint8_t *ctx, size_t ctxlen,
                         const uint8_t *sk);

int MLD_44_ref(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,
               const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);

int MLD_44_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m,
                      size_t mlen, const uint8_t *ctx, size_t ctxlen,
                      const uint8_t *pk);

int MLD_44_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,
                    const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

#endif /* !MLD_API_H */
