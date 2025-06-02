#ifndef __UNET_SNTRUP761_H
#define __UNET_SNTRUP761_H

#include <stdint.h>

#define SNTRUP761_CTEXT_SIZE	1039
#define SNTRUP761_SEC_SIZE	1763
#define SNTRUP761_PUB_SIZE	1158
#define SNTRUP761_BYTES		32

void sntrup761_set_batch(int val);
int sntrup761_keypair(uint8_t *pk, uint8_t *sk);
int sntrup761_enc(uint8_t *c, uint8_t *k, const uint8_t *pk);
int sntrup761_dec(uint8_t *k, const uint8_t *c, const uint8_t *sk);

#endif
