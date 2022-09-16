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

	if (fread(hdr->transaction, 12, 1, f) != 1)
		return NULL;

	fclose(f);
	memcpy(req->transaction, hdr->transaction, sizeof(req->transaction));
	req->pending = true;
	req->port = 0;
	*len = htons(hdr->msg_len) + sizeof(*hdr);

	return hdr;
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
	const void *tlv_data;
	uint16_t port;

	if (!req->pending)
		return false;

	if (!stun_msg_is_valid(data, len))
		return false;

	if (hdr->msg_type != htons(STUN_MSGTYPE_BINDING_RESPONSE))
		return false;

	if (memcmp(hdr->transaction, req->transaction, sizeof(hdr->transaction)) != 0)
		return false;

	stun_msg_parse(policy, tb, __PARSE_ATTR_MAX, data, len);

	if (tb[PARSE_ATTR_XOR_MAPPED]) {
		tlv_data = tb[PARSE_ATTR_XOR_MAPPED] + 1;
		tlv_data += 2;
		port = ntohs(*(const uint16_t *)tlv_data);
		port ^= STUN_MAGIC >> 16;
	} else if (tb[PARSE_ATTR_MAPPED]) {
		tlv_data = tb[PARSE_ATTR_MAPPED] + 1;
		tlv_data += 2;
		port = ntohs(*(const uint16_t *)tlv_data);
	} else
		return false;

	req->port = port;
	return true;
}
