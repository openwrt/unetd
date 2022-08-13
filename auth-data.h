// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __AUTH_DATA_H
#define __AUTH_DATA_H

#include <stdint.h>

#include <libubox/utils.h>

#include "edsign.h"
#include "curve25519.h"

#define UNET_AUTH_MAGIC 0x754e6574

struct unet_auth_hdr {
	uint32_t magic;

	uint8_t version;
	uint8_t _pad[3];

	uint8_t signature[EDSIGN_SIGNATURE_SIZE];
} __packed;

struct unet_auth_data {
	uint64_t timestamp;
	uint8_t pubkey[CURVE25519_KEY_SIZE];
	uint32_t flags;
} __packed;

int unet_auth_data_validate(const uint8_t *key, const void *buf, size_t len,
			    uint64_t *timestamp, const char **json_data);

static inline const struct unet_auth_data *
net_data_auth_data_hdr(const void *net_data)
{
	return net_data + sizeof(struct unet_auth_hdr);
}

#endif
