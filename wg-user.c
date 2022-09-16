// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 *
 * Based on wireguard-tools:
 *   Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include "unetd.h"

#define SOCK_PATH RUNSTATEDIR "/wireguard/"
#define SOCK_SUFFIX ".sock"

struct wg_req {
	FILE *f;

	char *buf;
	size_t buf_len;

	char *key, *value;

	int ret;
};

static void
key_to_hex(char hex[static WG_KEY_LEN_HEX], const uint8_t key[static WG_KEY_LEN])
{
	unsigned int i;

	for (i = 0; i < WG_KEY_LEN; ++i) {
		hex[i * 2] = 87U + (key[i] >> 4) + ((((key[i] >> 4) - 10U) >> 8) & ~38U);
		hex[i * 2 + 1] = 87U + (key[i] & 0xf) + ((((key[i] & 0xf) - 10U) >> 8) & ~38U);
	}

	hex[i * 2] = '\0';
}

static bool
key_from_hex(uint8_t key[static WG_KEY_LEN], const char *hex)
{
	uint8_t c, c_acc, c_alpha0, c_alpha, c_num0, c_num, c_val;
	volatile uint8_t ret = 0;

	if (strlen(hex) != WG_KEY_LEN_HEX - 1)
		return false;

	for (unsigned int i = 0; i < WG_KEY_LEN_HEX - 1; i += 2) {
		c = (uint8_t)hex[i];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		ret |= ((c_num0 | c_alpha0) - 1) >> 8;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		c_acc = c_val * 16U;

		c = (uint8_t)hex[i + 1];
		c_num = c ^ 48U;
		c_num0 = (c_num - 10U) >> 8;
		c_alpha = (c & ~32U) - 55U;
		c_alpha0 = ((c_alpha - 10U) ^ (c_alpha - 16U)) >> 8;
		ret |= ((c_num0 | c_alpha0) - 1) >> 8;
		c_val = (c_num0 & c_num) | (c_alpha0 & c_alpha);
		key[i / 2] = c_acc | c_val;
	}

	return 1 & ((ret - 1) >> 8);
}

static bool wg_user_check(struct network *net)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct stat sbuf;
	int fd, ret;

	if (snprintf(addr.sun_path, sizeof(addr.sun_path), SOCK_PATH "%s" SOCK_SUFFIX, network_name(net)) < 0)
		return false;
	if (stat(addr.sun_path, &sbuf) < 0)
		return false;
	if (!S_ISSOCK(sbuf.st_mode))
		return false;
	ret = fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret < 0)
		return false;
	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0 && errno == ECONNREFUSED) { /* If the process is gone, we try to clean up the socket. */
		close(fd);
		unlink(addr.sun_path);
		return false;
	}
	close(fd);
	return true;
}

static FILE *wg_user_file(struct network *net)
{
	struct stat sbuf;
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd = -1, ret;
	FILE *f = NULL;

	errno = EINVAL;
	ret = snprintf(addr.sun_path, sizeof(addr.sun_path), SOCK_PATH "%s" SOCK_SUFFIX, network_name(net));
	if (ret < 0)
		goto out;
	ret = stat(addr.sun_path, &sbuf);
	if (ret < 0)
		goto out;
	errno = EBADF;
	if (!S_ISSOCK(sbuf.st_mode))
		goto out;

	ret = fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ret < 0)
		goto out;

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		if (errno == ECONNREFUSED) /* If the process is gone, we try to clean up the socket. */
			unlink(addr.sun_path);
		goto out;
	}
	f = fdopen(fd, "r+");
	if (f)
		errno = 0;
out:
	ret = -errno;
	if (ret) {
		if (fd >= 0)
			close(fd);
		errno = -ret;
		return NULL;
	}
	return f;
}

static void wg_req_set(struct wg_req *req, const char *key, const char *value)
{
	fprintf(req->f, "%s=%s\n", key, value);
}

static void wg_req_set_int(struct wg_req *req, const char *key, int value)
{
	fprintf(req->f, "%s=%d\n", key, value);
}

#define wg_req_printf(req, name, format, ...) fprintf((req)->f, "%s=" format "\n", name, ##__VA_ARGS__)

static int wg_req_init(struct wg_req *req, struct network *net, bool set)
{
	memset(req, 0, sizeof(*req));
	req->ret = -1;
	req->f = wg_user_file(net);
	if (!req->f)
		return -1;

	wg_req_set(req, set ? "set" : "get", "1");

	return 0;
}

static bool wg_req_fetch(struct wg_req *req)
{
	int len;

	if (!req->buf) {
		fprintf(req->f, "\n");
		fflush(req->f);
	}

	if (getline(&req->buf, &req->buf_len, req->f) <= 0)
		return false;

	req->key = req->buf;
	len = strlen(req->key);
	if (len == 1 && req->key[0] == '\n')
		return false;

	req->value = strchr(req->key, '=');
	if (!req->value || !len || req->key[len - 1] != '\n')
		return false;

	*(req->value++) = req->key[--len] = 0;
	if (!strcmp(req->key, "errno"))
		req->ret = atoi(req->value);

	return true;
}

static void wg_req_complete(struct wg_req *req)
{
	while (wg_req_fetch(req));
}

static int wg_req_done(struct wg_req *req)
{
	if (!req->buf)
		wg_req_complete(req);

	if (req->f)
		fclose(req->f);
	free(req->buf);

	return -req->ret;
}

static int
wg_user_test(struct network *net)
{
	struct wg_req req;

	if (wg_req_init(&req, net, false))
		return -1;

	return wg_req_done(&req);
}

static int
wg_network_reset(struct network *net, uint8_t *key)
{
	struct wg_req req;
	char key_str[WG_KEY_LEN_HEX];

	if (wg_req_init(&req, net, true))
		return -1;

	wg_req_set(&req, "replace_peers", "true");

	key_to_hex(key_str, key);
	wg_req_set(&req, "private_key", key_str);

	return wg_req_done(&req);
}

static int
wg_user_init(struct network *net)
{
	int err;

	err = wg_user_test(net);
	if (err)
		return err;

	return wg_network_reset(net, net->config.key);
}

static void
wg_user_cleanup(struct network *net)
{
	uint8_t key[WG_KEY_LEN] = {};

	wg_network_reset(net, key);
}

static int
wg_user_init_local(struct network *net, struct network_peer *peer)
{
	struct wg_req req;

	if (wg_req_init(&req, net, true))
		return -1;

	wg_req_set_int(&req, "listen_port", peer ? peer->port : 0);

	return wg_req_done(&req);
}

static void
wg_user_peer_req_add_allowed_ip(struct wg_req *req, struct network_peer *peer)
{
	char addr[INET6_ADDRSTRLEN];
	struct blob_attr *cur;
	int rem;

	inet_ntop(AF_INET6, &peer->local_addr.in6, addr, sizeof(addr));
	wg_req_printf(req, "allowed_ip", "%s/128", addr);

	blobmsg_for_each_attr(cur, peer->ipaddr, rem) {
		const char *str = blobmsg_get_string(cur);
		struct in6_addr in6;
		int af, mask;

		if (strchr(str, ':')) {
			af = AF_INET6;
			mask = 128;
		} else {
			af = AF_INET;
			mask = 32;
		}

		if (inet_pton(af, str, &in6) != 1)
			continue;

		wg_req_printf(req, "allowed_ip", "%s/%d", str, mask);
	}

	blobmsg_for_each_attr(cur, peer->subnet, rem) {
		const char *str = blobmsg_get_string(cur);
		char buf[INET6_ADDRSTRLEN];
		union network_addr addr;
		int mask;
		int af;

		af = strchr(str, ':') ? AF_INET6 : AF_INET;
		if (network_get_subnet(af, &addr, &mask, str))
			continue;

		inet_ntop(af, &addr, buf, sizeof(buf));
		wg_req_printf(req, "allowed_ip", "%s/%d", buf, mask);
	}
}

static int
wg_user_peer_update(struct network *net, struct network_peer *peer, enum wg_update_cmd cmd)
{
	struct network_host *host;
	struct wg_req req;
	char key[WG_KEY_LEN_HEX];

	if (wg_req_init(&req, net, true))
		return -1;

	key_to_hex(key, peer->key);
	wg_req_set(&req, "public_key", key);

	if (cmd == WG_PEER_DELETE) {
		wg_req_set(&req, "remove", "true");
		goto out;
	}

	wg_req_set(&req, "replace_allowed_ips", "true");
	wg_user_peer_req_add_allowed_ip(&req, peer);
	for_each_routed_host(host, net, peer)
		wg_user_peer_req_add_allowed_ip(&req, &host->peer);

out:
	return wg_req_done(&req);
}

static int
wg_user_peer_refresh(struct network *net)
{
	struct network_peer *peer = NULL;
	struct wg_req req;
	uint8_t key[WG_KEY_LEN];
	time_t now = time(NULL);

	if (wg_req_init(&req, net, false))
		return -1;

	while (wg_req_fetch(&req)) {
		if (!strcmp(req.key, "public_key")) {
			if (peer)
				wg_peer_update_done(net, peer);
			if (key_from_hex(key, req.value))
				peer = wg_peer_update_start(net, key);
			else
				peer = NULL;
			continue;
		}

		if (!peer)
			continue;

		if (!strcmp(req.key, "last_handshake_time_sec")) {
			uint64_t sec = strtoull(req.value, NULL, 0);

			wg_peer_set_last_handshake(net, peer, now, sec);
			continue;
		}

		if (!strcmp(req.key, "rx_bytes")) {
			uint64_t bytes = strtoull(req.value, NULL, 0);

			wg_peer_set_rx_bytes(net, peer, bytes);
			continue;
		}

		if (!strcmp(req.key, "endpoint")) {
			struct addrinfo *resolved;
			struct addrinfo hints = {
				.ai_family = AF_UNSPEC,
				.ai_socktype = SOCK_DGRAM,
				.ai_protocol = IPPROTO_UDP,
			};
			char *port;

			if (!strlen(req.value))
				continue;

			if (req.value[0] == '[') {
				req.value++;
				port = strchr(req.value, ']');
				if (!port)
					continue;

				*port++ = 0;
				if (*port++ != ':')
					continue;
			} else {
				port = strchr(req.value, ':');
				if (!port)
					continue;

				*port++ = 0;
			}

			if (!*port)
				continue;

			if (getaddrinfo(req.value, port, &hints, &resolved) != 0)
				continue;

			if ((resolved->ai_family == AF_INET && resolved->ai_addrlen == sizeof(struct sockaddr_in)) ||
			    (resolved->ai_family == AF_INET6 && resolved->ai_addrlen == sizeof(struct sockaddr_in6)))
				wg_peer_set_endpoint(net, peer, resolved->ai_addr, resolved->ai_addrlen);

			freeaddrinfo(resolved);
			continue;
		}
	}

	if (peer)
		wg_peer_update_done(net, peer);

	return wg_req_done(&req);
}

static int
wg_user_peer_connect(struct network *net, struct network_peer *peer,
		      union network_endpoint *ep)
{
	struct wg_req req;
	char addr[INET6_ADDRSTRLEN];
	char key[WG_KEY_LEN_HEX];
	const void *ip;
	int port;

	if (wg_req_init(&req, net, true))
		return -1;

	key_to_hex(key, peer->key);
	wg_req_set(&req, "public_key", key);

	if (ep->in.sin_family == AF_INET6)
		ip = &ep->in6.sin6_addr;
	else
		ip = &ep->in.sin_addr;

	inet_ntop(ep->in.sin_family, ip, addr, sizeof(addr));
	port = ntohs(ep->in.sin_port);

	if (ep->in.sin_family == AF_INET6)
		wg_req_printf(&req, "endpoint", "[%s]:%d", addr, port);
	else
		wg_req_printf(&req, "endpoint", "%s:%d", addr, port);

	if (net->net_config.keepalive) {
		wg_req_set_int(&req, "persistent_keepalive_interval", 0);
		wg_req_set_int(&req, "persistent_keepalive_interval",
			       net->net_config.keepalive);
	}

	return wg_req_done(&req);
}

const struct wg_ops wg_user_ops = {
	.name = "user",
	.check = wg_user_check,
	.init = wg_user_init,
	.cleanup = wg_user_cleanup,
	.init_local = wg_user_init_local,
	.peer_update = wg_user_peer_update,
	.peer_refresh = wg_user_peer_refresh,
	.peer_connect = wg_user_peer_connect,
};
