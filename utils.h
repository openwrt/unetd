// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_UTILS_H
#define __UNETD_UTILS_H

#include <string.h>
#include <netinet/in.h>
#include <libubox/utils.h>

struct nl_msg;

union network_addr {
	struct {
		uint8_t network_id[8];
		uint8_t host_addr[8];
	};
	struct in_addr in;
	struct in6_addr in6;
};

union network_endpoint {
	struct sockaddr sa;
	struct sockaddr_in in;
	struct sockaddr_in6 in6;
};

static inline void *
network_endpoint_addr(union network_endpoint *ep, int *addr_len)
{
	if (ep->sa.sa_family == AF_INET6) {
		*addr_len = sizeof(ep->in6.sin6_addr);
		return &ep->in6.sin6_addr;
	}

	*addr_len = sizeof(ep->in.sin_addr);
	return &ep->in.sin_addr;
}

static inline bool
network_endpoint_addr_equal(union network_endpoint *ep1, union network_endpoint *ep2)
{
	const void *a1, *a2;
	int len;

	if (ep1->sa.sa_family != ep2->sa.sa_family)
		return false;

	a1 = network_endpoint_addr(ep1, &len);
	a2 = network_endpoint_addr(ep2, &len);

	return !memcmp(a1, a2, len);
}

int network_get_endpoint(union network_endpoint *dest, int af, const char *str,
			 int default_port, int idx);
int network_get_subnet(int af, union network_addr *addr, int *mask,
		       const char *str);
int network_get_local_addr(void *local, const union network_endpoint *target);

void *unet_read_file(const char *name, size_t *len);

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))

#define bitmask_size(len)	(4 * DIV_ROUND_UP(len, 32))

static inline bool bitmask_test(uint32_t *mask, unsigned int i)
{
	return mask[i / 32] & (1 << (i % 32));
}

static inline void bitmask_set(uint32_t *mask, unsigned int i)
{
	mask[i / 32] |= 1 << (i % 32);
}

static inline void bitmask_clear(uint32_t *mask, unsigned int i)
{
	mask[i / 32] &= ~(1 << (i % 32));
}

static inline void bitmask_set_val(uint32_t *mask, unsigned int i, bool val)
{
	if (val)
		bitmask_set(mask, i);
	else
		bitmask_clear(mask, i);
}

static inline uint16_t get_unaligned_be16(const uint8_t *p)
{
	return p[1] | p[0] << 8;
}

static inline uint32_t get_unaligned_be32(const uint8_t *p)
{
	return p[3] | p[2] << 8 | p[1] << 16 | p[0] << 24;
}

static inline uint64_t get_unaligned_be64(const uint8_t *p)
{
	return (uint64_t)get_unaligned_be32(p) << 32 |
	       get_unaligned_be32(p + 4);
}

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

int rtnl_init(void);
int rtnl_call(struct nl_msg *msg);

uint64_t unet_gettime(void);

int sendto_rawudp(int fd, const void *addr, void *ip_hdr, size_t ip_hdrlen,
		  const void *data, size_t len);

#endif
