// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include "stun.h"

static uint8_t tx_buf[256];

bool stun_msg_is_valid(const void *data, size_t len)
{
	const struct stun_msg_hdr *hdr = data;

	if (len <= sizeof(*hdr))
		return false;

	return hdr->magic == htonl(STUN_MAGIC);
}

static void *stun_msg_init(uint16_t type)
{
	struct stun_msg_hdr *hdr = (struct stun_msg_hdr *)tx_buf;

	memset(hdr, 0, sizeof(*hdr));
	hdr->msg_type = htons(type);
	hdr->magic = htonl(STUN_MAGIC);

	return hdr;
}

static void *stun_msg_add_tlv(uint16_t type, uint16_t len)
{
	struct stun_msg_hdr *hdr = (struct stun_msg_hdr *)tx_buf;
	uint16_t data_len = ntohs(hdr->msg_len);
	struct stun_msg_tlv *tlv;
	void *data = hdr + 1;

	data += data_len;

	tlv = data;
	tlv->type = htons(type);
	tlv->len = htons(len);

	if (len & 3)
		len = (len + 3) & ~3;

	data_len += sizeof(*tlv) + len;
	hdr->msg_len = htons(data_len);

	return tlv + 1;
}

static void
stun_msg_parse_attr(const struct stun_tlv_policy *policy,
		    const struct stun_msg_tlv **tb, int len,
		    const struct stun_msg_tlv *tlv)
{
	uint16_t type;
	int i;

	type = ntohs(tlv->type);

	for (i = 0; i < len; i++) {
		if (policy[i].type != type)
			continue;

		if (ntohs(tlv->len) < policy[i].min_len)
			return;

		tb[i] = tlv;
		return;
	}
}

static void
stun_msg_parse(const struct stun_tlv_policy *policy,
	       const struct stun_msg_tlv **tb, int len,
	       const void *data, size_t data_len)
{
	const struct stun_msg_hdr *hdr = data;
	const struct stun_msg_tlv *tlv;
	const void *end = data + data_len;
	uint16_t cur_len;

	memset(tb, 0, len * sizeof(*tb));

	data += sizeof(*hdr);
	while (1) {
		tlv = data;
		data = tlv + 1;
		if (data > end)
			break;

		cur_len = ntohs(tlv->len);
		if (data + cur_len > end)
			break;

		stun_msg_parse_attr(policy, tb, len, tlv);
		data += (cur_len + 3) & ~3;
	}
}

const void *stun_msg_request_prepare(struct stun_request *req, size_t *len,
				     uint16_t response_port)
{
	struct stun_msg_hdr *hdr;
	FILE *f;

	hdr = stun_msg_init(STUN_MSGTYPE_BINDING_REQUEST);
	if (response_port) {
		uint16_t *tlv_port = stun_msg_add_tlv(STUN_TLV_RESPONSE_PORT, 2);
		*tlv_port = htons(response_port);
	}

	f = fopen("/dev/urandom", "r");
	if (!f)
		return NULL;

	if (fread(hdr->transaction, 12, 1, f) != 1) {
		fclose(f);
		return NULL;
	}

	fclose(f);
	memcpy(req->transaction, hdr->transaction, sizeof(req->transaction));
	req->pending = true;
	req->port = 0;
	req->addr_len = 0;
	*len = htons(hdr->msg_len) + sizeof(*hdr);

	return hdr;
}

static bool
stun_msg_read_mapped(struct stun_request *req, const struct stun_msg_tlv *tlv,
		     bool xor)
{
	const uint8_t *val = (const uint8_t *)(tlv + 1);
	unsigned int len = ntohs(tlv->len);
	uint8_t mask[16] = {};
	unsigned int addr_len;
	unsigned int i;

	if (len < 4)
		return false;

	switch (val[1]) {
	case 1:
		addr_len = 4;
		break;
	case 2:
		addr_len = 16;
		break;
	default:
		return false;
	}

	if (len < 4 + addr_len)
		return false;

	if (xor) {
		mask[0] = (STUN_MAGIC >> 24) & 0xff;
		mask[1] = (STUN_MAGIC >> 16) & 0xff;
		mask[2] = (STUN_MAGIC >> 8) & 0xff;
		mask[3] = STUN_MAGIC & 0xff;
		memcpy(&mask[4], req->transaction, sizeof(req->transaction));
	}

	req->port = ntohs(*(const uint16_t *)&val[2]);
	if (xor)
		req->port ^= STUN_MAGIC >> 16;

	for (i = 0; i < addr_len; i++)
		req->addr[i] = val[4 + i] ^ mask[i];
	req->addr_len = addr_len;

	return true;
}

bool stun_msg_request_complete(struct stun_request *req, const void *data,
			       size_t len)
{
	enum {
		PARSE_ATTR_MAPPED,
		PARSE_ATTR_XOR_MAPPED,
		__PARSE_ATTR_MAX
	};
	const struct stun_msg_tlv *tb[__PARSE_ATTR_MAX];
	static const struct stun_tlv_policy policy[__PARSE_ATTR_MAX] = {
		[PARSE_ATTR_MAPPED] = { STUN_TLV_MAPPED_ADDRESS, 8 },
		[PARSE_ATTR_XOR_MAPPED] = { STUN_TLV_XOR_MAPPED_ADDRESS, 8 }
	};
	const struct stun_msg_hdr *hdr = data;

	if (!req->pending)
		return false;

	if (!stun_msg_is_valid(data, len))
		return false;

	if (hdr->msg_type != htons(STUN_MSGTYPE_BINDING_RESPONSE))
		return false;

	if (memcmp(hdr->transaction, req->transaction, sizeof(hdr->transaction)) != 0)
		return false;

	stun_msg_parse(policy, tb, __PARSE_ATTR_MAX, data, len);

	if (tb[PARSE_ATTR_XOR_MAPPED])
		return stun_msg_read_mapped(req, tb[PARSE_ATTR_XOR_MAPPED], true);

	if (tb[PARSE_ATTR_MAPPED])
		return stun_msg_read_mapped(req, tb[PARSE_ATTR_MAPPED], false);

	return false;
}
