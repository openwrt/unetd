#ifndef __UNETD_STUN_H
#define __UNETD_STUN_H

#include <stdint.h>
#include <stdbool.h>

#define STUN_MSGTYPE_BINDING_REQUEST		0x0001
#define STUN_MSGTYPE_BINDING_RESPONSE		0x0101
#define STUN_MSGTYPE_BINDING_ERROR		0x0111
#define STUN_MSGTYPE_BINDING_INDICATION		0x0011

#define STUN_MSGTYPE_SHARED_SECRET_REQUEST	0x0002
#define STUN_MSGTYPE_SHARED_SECRET_RESPONSE	0x0102
#define STUN_MSGTYPE_SHARED_SECRET_ERROR	0x0112

#define STUN_MAGIC				0x2112a442

enum tlv_type {
	STUN_TLV_MAPPED_ADDRESS =		0x01,
	STUN_TLV_RESPONSE_ADDRESS =		0x02,
	STUN_TLV_CHANGE_REQUEST =		0x03,
	STUN_TLV_SOURCE_ADDRESS =		0x04,
	STUN_TLV_CHANGED_ADDRESS =		0x05,
	STUN_TLV_XOR_MAPPED_ADDRESS =		0x20,
	STUN_TLV_RESPONSE_PORT =		0x27,
};

struct stun_msg_hdr {
	uint16_t msg_type;
	uint16_t msg_len;
	uint32_t magic;
	uint8_t transaction[12];
};

struct stun_msg_tlv {
	uint16_t type;
	uint16_t len;
};

struct stun_tlv_policy {
	uint16_t type;
	uint16_t min_len;
};

struct stun_request {
	uint8_t transaction[12];
	uint16_t port;
	bool pending;
};

bool stun_msg_is_valid(const void *data, size_t len);
const void *stun_msg_request_prepare(struct stun_request *req, size_t *len,
				     uint16_t response_port);
bool stun_msg_request_complete(struct stun_request *req, const void *data,
			       size_t len);

#endif
