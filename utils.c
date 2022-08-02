// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
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
	freeaddrinfo(ai_cur);

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
