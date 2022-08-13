// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include "edsign.h"
#include "ed25519.h"
#include "auth-data.h"

int unet_auth_data_validate(const uint8_t *key, const void *buf, size_t len,
			    uint64_t *timestamp, const char **json_data)
{
	const struct unet_auth_hdr *hdr = buf;
	const struct unet_auth_data *data = net_data_auth_data_hdr(buf);
	struct edsign_verify_state vst;

	if (len <= sizeof(*hdr) + sizeof(*data))
		return -1;

	len -= sizeof(*hdr);

	if (hdr->magic != cpu_to_be32(UNET_AUTH_MAGIC) ||
	    hdr->version != 0 || data->flags != 0 ||
	    data->timestamp == 0)
		return -1;

	if (key && memcmp(data->pubkey, key, EDSIGN_PUBLIC_KEY_SIZE) != 0)
		return -2;

	edsign_verify_init(&vst, hdr->signature, data->pubkey);
	edsign_verify_add(&vst, data, len);
	if (!edsign_verify(&vst, hdr->signature, data->pubkey))
		return -3;

	if (*(char *)(data + len - 1) != 0)
		return -2;

	if (timestamp)
		*timestamp = be64_to_cpu(data->timestamp);

	if (json_data)
		*json_data = (const char *)(data + 1);

	return 0;
}
