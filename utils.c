// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <libubox/utils.h>

#include "unetd.h"

int network_get_endpoint(union network_endpoint *dest, const char *str,
			 int default_port, int idx)
{
	struct addrinfo hints = {
		.ai_flags = AI_ADDRCONFIG,
		.ai_family = AF_UNSPEC,
	};
	char *buf = strdup(str);
	char *host = buf, *port;
	struct addrinfo *ai, *ai_cur;
	int n_res;
	int ret = -1;

	memset(dest, 0, sizeof(*dest));

	if (*host == '[') {
		host++;
		port = strchr(host, ']');
		if (!port)
			goto out;

		*(port++) = 0;
		if (!*port)
			port = NULL;
		else if (*port == ':')
			port++;
		else
			goto out;
		hints.ai_family = AF_INET6;
		hints.ai_flags |= AI_NUMERICHOST;
	} else {
		host = buf;

		port = strchr(host, ':');
		if (port)
			*(port++) = 0;
	}

	if (getaddrinfo(host, port, &hints, &ai) || !ai)
		goto out;

	while (1) {
		ai_cur = ai;
		for (n_res = 0; ai_cur; ai_cur = ai_cur->ai_next, n_res++)
			if (!idx--)
				goto found;

		idx %= n_res;
	}

found:
	if (ai_cur->ai_addrlen > sizeof(*dest))
		goto free_ai;

	memcpy(dest, ai_cur->ai_addr, ai_cur->ai_addrlen);
	if (!port)
		dest->in.sin_port = htons(default_port);
	ret = 0;

free_ai:
	freeaddrinfo(ai);

out:
	free(buf);
	return ret;
}

int network_get_subnet(int af, union network_addr *addr, int *mask, const char *str)
{
	char *buf = strdup(str);
	char *sep, *end;
	int ret = -1;

	if (af == AF_INET6)
		*mask = 128;
	else
		*mask = 32;

	sep = strchr(buf, '/');
	if (sep) {
		unsigned long val;

		*(sep++) = 0;

		val = strtoul(sep, &end, 0);
		if ((end && *end) || val > *mask)
			goto out;

		*mask = val;
	}

	if (inet_pton(af, buf, addr) == 1)
		ret = 0;

out:
	free(buf);
	return ret;
}

int network_get_local_addr(void *local, const union network_endpoint *target)
{
	union network_endpoint ep = {};
	socklen_t len;
	int ret = -1;
	int fd;

	memset(local, 0, sizeof(union network_addr));
	if (target->sa.sa_family == AF_INET6)
		len = sizeof(ep.in6);
	else
		len = sizeof(ep.in);

	fd = socket(target->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		return -1;

	if (connect(fd, (const struct sockaddr *)target, len))
		goto out;

	len = sizeof(ep);
	if (getsockname(fd, &ep.sa, &len))
		goto out;

	if (ep.sa.sa_family == AF_INET6)
		memcpy(local, &ep.in6.sin6_addr, sizeof(ep.in6.sin6_addr));
	else
		memcpy(local, &ep.in.sin_addr, sizeof(ep.in.sin_addr));
	ret = 0;

out:
	close(fd);
	return ret;
}

void *unet_read_file(const char *name, size_t *len)
{
	struct stat st;
	void *data;
	FILE *f;

	f = fopen(name, "r");
	if (!f)
		goto error;

	if (fstat(fileno(f), &st) < 0)
		goto close;

	if (*len && st.st_size > *len)
		goto close;

	data = malloc(st.st_size);
	if (!data)
		goto close;

	if (fread(data, 1, st.st_size, f) != st.st_size) {
		free(data);
		goto close;
	}
	fclose(f);

	*len = st.st_size;
	return data;

close:
	fclose(f);
error:
	*len = 0;
	return NULL;
}

uint64_t unet_gettime(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);

	return ts.tv_sec;
}

static inline uint32_t
csum_tcpudp_nofold(uint32_t saddr, uint32_t daddr, uint32_t len, uint8_t proto)
{
	uint64_t sum = 0;

	sum += saddr;
	sum += daddr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	sum += (proto + len) << 8;
#else
	sum += proto + len;
#endif

	sum = (sum & 0xffffffff) + (sum >> 32);
	sum = (sum & 0xffffffff) + (sum >> 32);

	return (uint32_t)sum;
}

static inline uint32_t csum_add(uint32_t sum, uint32_t addend)
{
	sum += addend;
	return sum + (sum < addend);
}

static inline uint16_t csum_fold(uint32_t sum)
{
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return (uint16_t)~sum;
}

static uint32_t csum_partial(const void *buf, int len)
{
	const uint16_t *data = buf;
	uint32_t sum = 0;

	while (len > 1) {
		sum += *data++;
		len -= 2;
	}

	if (len == 1)
#if __BYTE_ORDER == __LITTLE_ENDIAN
		sum += *(uint8_t *)data;
#else
		sum += *(uint8_t *)data << 8;
#endif

	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);

	return sum;
}

static void fixup_udpv4(void *hdr, size_t hdrlen, const void *data, size_t len)
{
	struct ip *ip = hdr;
	struct udphdr *udp = hdr + ip->ip_hl * 4;
	uint16_t udp_len = sizeof(*udp) + len;
	uint32_t sum;

	if ((void *)&udp[1] > hdr + hdrlen)
		return;

	udp->uh_sum = 0;
	udp->uh_ulen = htons(udp_len);
	sum = csum_tcpudp_nofold(*(uint32_t *)&ip->ip_src, *(uint32_t *)&ip->ip_dst,
				 ip->ip_p, udp_len);
	sum = csum_add(sum, csum_partial(udp, sizeof(*udp)));
	sum = csum_add(sum, csum_partial(data, len));
	udp->uh_sum = csum_fold(sum);

	ip->ip_len = htons(hdrlen + len);
	ip->ip_sum = 0;
	ip->ip_sum = csum_fold(csum_partial(ip, sizeof(*ip)));

#ifdef __APPLE__
	ip->ip_len = hdrlen + len;
#endif
}

static void fixup_udpv6(void *hdr, size_t hdrlen, const void *data, size_t len)
{
	struct ip6_hdr *ip = hdr;
	struct udphdr *udp = hdr + sizeof(*ip);
	uint16_t udp_len = htons(sizeof(*udp) + len);

	if ((void *)&udp[1] > hdr + hdrlen)
		return;

	ip->ip6_plen = htons(sizeof(*udp) + len);
	udp->uh_sum = 0;
	udp->uh_ulen = udp_len;
	udp->uh_sum = csum_fold(csum_partial(hdr, sizeof(*ip) + sizeof(*udp)));

#ifdef __APPLE__
	ip->ip6_plen = sizeof(*udp) + len;
#endif
}

static void fixup_ip_udp_header(void *hdr, size_t hdrlen, const void *data, size_t len)
{
	if (hdrlen >= sizeof(struct ip6_hdr) + sizeof(struct udphdr))
		fixup_udpv6(hdr, hdrlen, data, len);
	else if (hdrlen >= sizeof(struct ip) + sizeof(struct udphdr))
		fixup_udpv4(hdr, hdrlen, data, len);
}

int sendto_rawudp(int fd, const void *addr, void *ip_hdr, size_t ip_hdrlen,
		  const void *data, size_t len)
{
	const struct sockaddr *sa = addr;
	struct iovec iov[2] = {
		{ .iov_base = ip_hdr, .iov_len = ip_hdrlen },
		{ .iov_base = (void *)data, .iov_len = len }
	};
	struct msghdr msg = {
		.msg_name = (void *)addr,
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};

	if (sa->sa_family == AF_INET6)
		msg.msg_namelen = sizeof(struct sockaddr_in6);
	else
		msg.msg_namelen = sizeof(struct sockaddr_in);

	fixup_ip_udp_header(ip_hdr, ip_hdrlen, data, len);

	return sendmsg(fd, &msg, 0);
}
