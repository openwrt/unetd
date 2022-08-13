// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include "pex-msg.h"
#include "chacha20.h"
#include "auth-data.h"

static char pex_tx_buf[PEX_BUF_SIZE];
static FILE *pex_urandom;
static struct uloop_fd pex_fd;
static LIST_HEAD(requests);
static struct uloop_timeout gc_timer;

static pex_recv_cb_t pex_recv_cb;

struct pex_msg_update_recv_ctx {
	struct list_head list;

	union network_endpoint addr;

	uint8_t priv_key[CURVE25519_KEY_SIZE];
	uint8_t auth_key[CURVE25519_KEY_SIZE];
	uint8_t e_key[CURVE25519_KEY_SIZE];

	uint64_t req_id;

	void *data;
	int data_len;
	int data_ofs;

	int idle;
};

uint64_t pex_network_hash(const uint8_t *auth_key, uint64_t req_id)
{
	siphash_key_t key = {
		be64_to_cpu(req_id),
		be64_to_cpu(req_id)
	};
	uint64_t hash;

	siphash_to_be64(&hash, auth_key, CURVE25519_KEY_SIZE, &key);

	return hash;
}


struct pex_hdr *__pex_msg_init(const uint8_t *pubkey, uint8_t opcode)
{
	struct pex_hdr *hdr = (struct pex_hdr *)pex_tx_buf;

	hdr->version = 0;
	hdr->opcode = opcode;
	hdr->len = 0;
	memcpy(hdr->id, pubkey, sizeof(hdr->id));

	return hdr;
}

struct pex_hdr *__pex_msg_init_ext(const uint8_t *pubkey, const uint8_t *auth_key,
				   uint8_t opcode, bool ext)
{
	struct pex_hdr *hdr = __pex_msg_init(pubkey, opcode);
	struct pex_ext_hdr *ehdr = (struct pex_ext_hdr *)(hdr + 1);
	uint64_t hash;

	if (!ext)
		return hdr;

	hdr->len = sizeof(*ehdr);

	fread(&ehdr->nonce, sizeof(ehdr->nonce), 1, pex_urandom);

	hash = pex_network_hash(auth_key, ehdr->nonce);
	*(uint64_t *)hdr->id ^= hash;
	memcpy(ehdr->auth_id, auth_key, sizeof(ehdr->auth_id));

	return hdr;
}

void *pex_msg_append(size_t len)
{
	struct pex_hdr *hdr = (struct pex_hdr *)pex_tx_buf;
	int ofs = hdr->len + sizeof(struct pex_hdr);
	void *buf = &pex_tx_buf[ofs];

	if (sizeof(pex_tx_buf) - ofs < len)
		return NULL;

	hdr->len += len;
	memset(buf, 0, len);

	return buf;
}

static void
pex_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	struct sockaddr_in6 sin6;
	static char buf[PEX_BUF_SIZE];
	struct pex_hdr *hdr = (struct pex_hdr *)buf;
	ssize_t len;

	while (1) {
		socklen_t slen = sizeof(sin6);

		len = recvfrom(fd->fd, buf, sizeof(buf), 0, (struct sockaddr *)&sin6, &slen);
		if (len < 0) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN)
				break;

			pex_close();
			return;
		}

		if (!len)
			continue;

		if (len < sizeof(*hdr) + sizeof(struct pex_ext_hdr))
			continue;

		hdr->len = ntohs(hdr->len);
		if (len - sizeof(hdr) - sizeof(struct pex_ext_hdr) < hdr->len)
			continue;

		pex_recv_cb(hdr, &sin6);
	}
}

int __pex_msg_send(int fd, const void *addr)
{
	struct pex_hdr *hdr = (struct pex_hdr *)pex_tx_buf;
	const struct sockaddr *sa = addr;
	size_t tx_len = sizeof(*hdr) + hdr->len;
	uint16_t orig_len = hdr->len;
	size_t addr_len;
	int ret;

	if (fd < 0) {
		hdr->len -= sizeof(struct pex_ext_hdr);
		fd = pex_fd.fd;
	}

	hdr->len = htons(hdr->len);
	if (addr) {
		if (sa->sa_family == AF_INET6)
			addr_len = sizeof(struct sockaddr_in6);
		else
			addr_len = sizeof(struct sockaddr_in);
		ret = sendto(fd, pex_tx_buf, tx_len, 0, sa, addr_len);
	} else {
		ret = send(fd, pex_tx_buf, tx_len, 0);
	}
	hdr->len = orig_len;

	return ret;
}

static void
pex_msg_update_response_fill(struct pex_msg_update_send_ctx *ctx)
{
	struct pex_hdr *hdr = (struct pex_hdr *)pex_tx_buf;
	int ofs = hdr->len + sizeof(struct pex_hdr);
	int cur_len = ctx->rem;

	if (cur_len > PEX_BUF_SIZE - ofs)
		cur_len = PEX_BUF_SIZE - ofs;

	memcpy(pex_msg_append(cur_len), ctx->cur, cur_len);
	ctx->cur += cur_len;
	ctx->rem -= cur_len;
}

void pex_msg_update_response_init(struct pex_msg_update_send_ctx *ctx,
				  const uint8_t *pubkey, const uint8_t *auth_key,
				  const uint8_t *peer_key, bool ext,
				  struct pex_update_request *req,
				  const void *data, int len)
{
	uint8_t e_key_priv[CURVE25519_KEY_SIZE];
	uint8_t enc_key[CURVE25519_KEY_SIZE];
	struct pex_update_response *res;

	ctx->pubkey = pubkey;
	ctx->auth_key = auth_key;
	ctx->ext = ext;
	ctx->req_id = req->req_id;

	__pex_msg_init_ext(pubkey, auth_key, PEX_MSG_UPDATE_RESPONSE, ext);
	res = pex_msg_append(sizeof(*res));
	res->req_id = req->req_id;
	res->data_len = len;

	fread(e_key_priv, sizeof(e_key_priv), 1, pex_urandom);
	curve25519_clamp_secret(e_key_priv);
	curve25519_generate_public(res->e_key, e_key_priv);
	curve25519(enc_key, e_key_priv, peer_key);

	ctx->data = ctx->cur = malloc(len);
	ctx->rem = len;

	memcpy(ctx->data, data, len);
	chacha20_encrypt_msg(ctx->data, len, &req->req_id, enc_key);

	pex_msg_update_response_fill(ctx);
}

bool pex_msg_update_response_continue(struct pex_msg_update_send_ctx *ctx)
{
	struct pex_update_response_data *res_ext;

	if (ctx->rem <= 0) {
		free(ctx->data);
		ctx->data = NULL;

		return false;
	}

	__pex_msg_init_ext(ctx->pubkey, ctx->auth_key,
			   PEX_MSG_UPDATE_RESPONSE_DATA, ctx->ext);
	res_ext = pex_msg_append(sizeof(*res_ext));
	res_ext->req_id = ctx->req_id;
	res_ext->offset = ctx->cur - ctx->data;
	pex_msg_update_response_fill(ctx);

	return true;
}


struct pex_update_request *
pex_msg_update_request_init(const uint8_t *pubkey, const uint8_t *priv_key,
			    const uint8_t *auth_key, union network_endpoint *addr,
			    uint64_t cur_version, bool ext)
{
	struct pex_update_request *req;
	struct pex_msg_update_recv_ctx *ctx;

	list_for_each_entry(ctx, &requests, list) {
		if (!memcmp(&ctx->addr, addr, sizeof(ctx->addr)))
			return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	memcpy(&ctx->addr, addr, sizeof(ctx->addr));
	memcpy(ctx->auth_key, auth_key, sizeof(ctx->auth_key));
	memcpy(ctx->priv_key, priv_key, sizeof(ctx->priv_key));
	fread(&ctx->req_id, sizeof(ctx->req_id), 1, pex_urandom);
	list_add_tail(&ctx->list, &requests);
	if (!gc_timer.pending)
		uloop_timeout_set(&gc_timer, 1000);

	__pex_msg_init_ext(pubkey, auth_key, PEX_MSG_UPDATE_REQUEST, ext);
	req = pex_msg_append(sizeof(*req));
	req->cur_version = cpu_to_be64(cur_version);
	req->req_id = ctx->req_id;

	return req;
}

static struct pex_msg_update_recv_ctx *
pex_msg_update_recv_ctx_get(uint64_t req_id)
{
	struct pex_msg_update_recv_ctx *ctx;

	list_for_each_entry(ctx, &requests, list) {
		if (ctx->req_id == req_id) {
			ctx->idle = 0;
			return ctx;
		}
	}

	return NULL;
}

static void pex_msg_update_ctx_free(struct pex_msg_update_recv_ctx *ctx)
{
	list_del(&ctx->list);
	free(ctx->data);
	free(ctx);
}

void *pex_msg_update_response_recv(const void *data, int len, enum pex_opcode op,
				   int *data_len, uint64_t *timestamp)
{
	struct pex_msg_update_recv_ctx *ctx;
	uint8_t enc_key[CURVE25519_KEY_SIZE];
	void *ret;

	*data_len = 0;
	if (op == PEX_MSG_UPDATE_RESPONSE) {
		const struct pex_update_response *res = data;

		if (len < sizeof(*res))
			return NULL;

		ctx = pex_msg_update_recv_ctx_get(res->req_id);
		if (!ctx || ctx->data_len || !res->data_len ||
		    res->data_len > UNETD_NET_DATA_SIZE_MAX)
			return NULL;

		data += sizeof(*res);
		len -= sizeof(*res);

		ctx->data_len = res->data_len;
		memcpy(ctx->e_key, res->e_key, sizeof(ctx->e_key));
		ctx->data = malloc(ctx->data_len);
	} else if (op == PEX_MSG_UPDATE_RESPONSE_DATA) {
		const struct pex_update_response_data *res = data;

		if (len <= sizeof(*res))
			return NULL;

		ctx = pex_msg_update_recv_ctx_get(res->req_id);
		if (!ctx || ctx->data_ofs != res->offset)
			return NULL;

		data += sizeof(*res);
		len -= sizeof(*res);
	} else if (op == PEX_MSG_UPDATE_RESPONSE_NO_DATA) {
		const struct pex_update_response_no_data *res = data;

		if (len < sizeof(*res))
			return NULL;

		ctx = pex_msg_update_recv_ctx_get(res->req_id);
		if (!ctx)
			return NULL;

		goto error;
	} else {
		return NULL;
	}

	if (ctx->data_ofs + len > ctx->data_len)
		goto error;

	memcpy(ctx->data + ctx->data_ofs, data, len);
	ctx->data_ofs += len;
	if (ctx->data_ofs < ctx->data_len)
		return NULL;

	curve25519(enc_key, ctx->priv_key, ctx->e_key);
	chacha20_encrypt_msg(ctx->data, ctx->data_len, &ctx->req_id, enc_key);
	if (unet_auth_data_validate(ctx->auth_key, ctx->data, ctx->data_len, timestamp, NULL))
		goto error;

	*data_len = ctx->data_len;
	ret = ctx->data;
	ctx->data = NULL;
	pex_msg_update_ctx_free(ctx);

	return ret;

error:
	pex_msg_update_ctx_free(ctx);
	*data_len = -1;
	return NULL;
}

static void
pex_gc_cb(struct uloop_timeout *t)
{
	struct pex_msg_update_recv_ctx *ctx, *tmp;

	list_for_each_entry_safe(ctx, tmp, &requests, list) {
		if (++ctx->idle <= 3)
			continue;

		pex_msg_update_ctx_free(ctx);
	}

	if (!list_empty(&requests))
		uloop_timeout_set(t, 1000);
}

int pex_open(void *addr, size_t addr_len, pex_recv_cb_t cb, bool server)
{
	struct sockaddr *sa = addr;
	int yes = 1, no = 0;
	int fd;

	pex_recv_cb = cb;

	pex_urandom = fopen("/dev/urandom", "r");
	if (!pex_urandom)
		return -1;

	fd = socket(sa->sa_family == AF_INET ? PF_INET : PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0)
		goto close_urandom;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	if (server) {
		if (bind(fd, addr, addr_len) < 0) {
			perror("bind");
			goto close_socket;
		}

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
	} else {
		if (connect(fd, addr, addr_len) < 0) {
			perror("connect");
			goto close_socket;
		}
	}

	pex_fd.fd = fd;
	pex_fd.cb = pex_fd_cb;
	uloop_fd_add(&pex_fd, ULOOP_READ);

	gc_timer.cb = pex_gc_cb;

	return 0;

close_socket:
	close(fd);
close_urandom:
	fclose(pex_urandom);
	return -1;
}

void pex_close(void)
{
	if (!pex_fd.cb)
		return;

	fclose(pex_urandom);
	uloop_fd_delete(&pex_fd);
	close(pex_fd.fd);
	pex_fd.cb = NULL;
	pex_urandom = NULL;
}
