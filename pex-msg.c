// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/usock.h>
#include "pex-msg.h"
#include "chacha20.h"
#include "auth-data.h"

static char pex_tx_buf[PEX_BUF_SIZE];
static FILE *pex_urandom;
static struct uloop_fd pex_fd, pex_unix_fd;
static LIST_HEAD(requests);
static struct uloop_timeout gc_timer;
static int pex_raw_v4_fd = -1, pex_raw_v6_fd = -1;

static pex_recv_cb_t pex_recv_cb;
static pex_recv_control_cb_t pex_control_cb;
static int pex_unix_tx_fd = -1;

int pex_socket(void)
{
	return pex_fd.fd;
}

int pex_raw_socket(int family)
{
	return family == AF_INET ? pex_raw_v4_fd : pex_raw_v6_fd;
}

static const void *
get_mapped_sockaddr(const void *addr)
{
	static struct sockaddr_in6 sin6;
	const struct sockaddr_in *sin = addr;

	if (!sin || sin->sin_family != AF_INET)
		return addr;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr.s6_addr[10] = 0xff;
	sin6.sin6_addr.s6_addr[11] = 0xff;
	memcpy(&sin6.sin6_addr.s6_addr[12], &sin->sin_addr, sizeof(struct in_addr));
	sin6.sin6_port = sin->sin_port;

	return &sin6;
}

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
		.key = {
			be64_to_cpu(req_id),
			be64_to_cpu(req_id)
		}
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

	if (fread(&ehdr->nonce, sizeof(ehdr->nonce), 1, pex_urandom) != 1)
		return NULL;

	hash = pex_network_hash(auth_key, ehdr->nonce);
	*(uint64_t *)hdr->id ^= hash;
	memcpy(ehdr->auth_id, auth_key, sizeof(ehdr->auth_id));

	return hdr;
}

void *pex_msg_tail(void)
{
	struct pex_hdr *hdr = (struct pex_hdr *)pex_tx_buf;

	return &pex_tx_buf[hdr->len + sizeof(struct pex_hdr)];
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
	static struct sockaddr_in6 sin6;
	static char buf[PEX_RX_BUF_SIZE];
	ssize_t len;

	while (1) {
		static struct iovec iov[2] = {
			{ .iov_base = &sin6 },
			{ .iov_base = buf },
		};
		static struct msghdr msg = {
			.msg_iov = iov,
			.msg_iovlen = ARRAY_SIZE(iov),
		};
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

		if (IN6_IS_ADDR_V4MAPPED(&sin6.sin6_addr)) {
			struct sockaddr_in *sin = (struct sockaddr_in *)&sin6;
			struct in_addr in = *(struct in_addr *)&sin6.sin6_addr.s6_addr[12];
			int port = sin6.sin6_port;

			memset(&sin6, 0, sizeof(sin6));
			sin->sin_port = port;
			sin->sin_family = AF_INET;
			sin->sin_addr = in;
			slen = sizeof(*sin);
		}

retry:
		if (pex_unix_tx_fd >= 0) {
			iov[0].iov_len = slen;
			iov[1].iov_len = len;
			if (sendmsg(pex_unix_tx_fd, &msg, 0) < 0) {
				switch (errno) {
				case EINTR:
					goto retry;
				case EMSGSIZE:
				case ENOBUFS:
				case EAGAIN:
					continue;
				default:
					perror("sendmsg");
					close(pex_unix_tx_fd);
					pex_unix_tx_fd = -1;
					break;
				}
			}
		}

		pex_recv_cb(buf, len, &sin6);
	}
}

static void
pex_unix_cb(struct uloop_fd *fd, unsigned int events)
{
	static char buf[PEX_RX_BUF_SIZE];
	static struct iovec iov = {
		.iov_base = buf,
		.iov_len = sizeof(buf),
	};
	ssize_t len;

	while (1) {
		const struct sockaddr *sa = (struct sockaddr *)buf;
		uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = { 0 };
		struct msghdr msg = {
			.msg_iov = &iov,
			.msg_iovlen = 1,
			.msg_control = fd_buf,
			.msg_controllen = CMSG_LEN(sizeof(int)),
		};
		struct cmsghdr *cmsg;
		socklen_t slen;
		int *pfd;

		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_type = SCM_RIGHTS;
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_len = CMSG_LEN(sizeof(int));

		pfd = (int *)CMSG_DATA(cmsg);
		*pfd = -1;

		len = recvmsg(fd->fd, &msg, 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN)
				break;

			pex_close();
			return;
		}

		if (*pfd >= 0) {
			if (pex_unix_tx_fd >= 0)
				close(pex_unix_tx_fd);

			pex_unix_tx_fd = *pfd;
		}

		if (!len)
			continue;

		if (len < sizeof(*sa))
			continue;

		if (sa->sa_family == AF_LOCAL) {
			slen = sizeof(struct sockaddr);
			len -= slen;
			if (len < sizeof(struct pex_msg_local_control))
				continue;

			if (pex_control_cb)
				pex_control_cb((struct pex_msg_local_control *)&buf[slen], len);

			continue;
		}

		if (sa->sa_family == AF_INET)
			slen = sizeof(struct sockaddr_in);
		else if (sa->sa_family == AF_INET6)
			slen = sizeof(struct sockaddr_in6);
		else
			continue;

		sa = get_mapped_sockaddr(sa);
		sendto(pex_fd.fd, buf + slen, len - slen, 0, sa, sizeof(struct sockaddr_in6));
	}
}


int __pex_msg_send(int fd, const void *addr, void *ip_hdr, size_t ip_hdrlen)
{
	struct pex_hdr *hdr = (struct pex_hdr *)pex_tx_buf;
	const struct sockaddr *sa = addr;
	size_t tx_len = sizeof(*hdr) + hdr->len;
	uint16_t orig_len = hdr->len;
	int ret;

	if (fd < 0) {
		hdr->len -= sizeof(struct pex_ext_hdr);
		if (ip_hdrlen)
			fd = pex_raw_socket(sa->sa_family);
		else {
			fd = pex_fd.fd;
			sa = addr = get_mapped_sockaddr(addr);
		}

		if (fd < 0)
			return -1;
	}

	hdr->len = htons(hdr->len);
	if (ip_hdr) {
		ret = sendto_rawudp(fd, addr, ip_hdr, ip_hdrlen, pex_tx_buf, tx_len);
	} else if (addr) {
		socklen_t addr_len;

		if (sa->sa_family == AF_INET6)
			addr_len = sizeof(struct sockaddr_in6);
		else
			addr_len = sizeof(struct sockaddr_in);

		ret = sendto(fd, pex_tx_buf, tx_len, 0, addr, addr_len);
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

	if (!__pex_msg_init_ext(pubkey, auth_key, PEX_MSG_UPDATE_RESPONSE, ext))
		return;

	res = pex_msg_append(sizeof(*res));
	res->req_id = req->req_id;
	res->data_len = cpu_to_be32(len);

	if (!fread(e_key_priv, sizeof(e_key_priv), 1, pex_urandom))
		return;

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

	if (!__pex_msg_init_ext(ctx->pubkey, ctx->auth_key,
				PEX_MSG_UPDATE_RESPONSE_DATA, ctx->ext))
		return false;

	res_ext = pex_msg_append(sizeof(*res_ext));
	res_ext->req_id = ctx->req_id;
	res_ext->offset = cpu_to_be32(ctx->cur - ctx->data);
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
	if (!fread(&ctx->req_id, sizeof(ctx->req_id), 1, pex_urandom)) {
		free(ctx);
		return NULL;
	}
	list_add_tail(&ctx->list, &requests);
	if (!gc_timer.pending)
		uloop_timeout_set(&gc_timer, 1000);

	if (!__pex_msg_init_ext(pubkey, auth_key, PEX_MSG_UPDATE_REQUEST, ext)) {
		free(ctx);
		return NULL;
	}

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

	if (timestamp)
		*timestamp = 0;
	*data_len = 0;
	if (op == PEX_MSG_UPDATE_RESPONSE) {
		const struct pex_update_response *res = data;

		if (len < sizeof(*res))
			return NULL;

		ctx = pex_msg_update_recv_ctx_get(res->req_id);
		if (!ctx || ctx->data_len || !res->data_len ||
		    be32_to_cpu(res->data_len) > UNETD_NET_DATA_SIZE_MAX)
			return NULL;

		data += sizeof(*res);
		len -= sizeof(*res);

		ctx->data_len = be32_to_cpu(res->data_len);
		memcpy(ctx->e_key, res->e_key, sizeof(ctx->e_key));
		ctx->data = malloc(ctx->data_len);
	} else if (op == PEX_MSG_UPDATE_RESPONSE_DATA) {
		const struct pex_update_response_data *res = data;

		if (len <= sizeof(*res))
			return NULL;

		ctx = pex_msg_update_recv_ctx_get(res->req_id);
		if (!ctx || ctx->data_ofs != be32_to_cpu(res->offset))
			return NULL;

		data += sizeof(*res);
		len -= sizeof(*res);
	} else if (op == PEX_MSG_UPDATE_RESPONSE_NO_DATA ||
	           op == PEX_MSG_UPDATE_RESPONSE_REFUSED) {
		const struct pex_update_response_no_data *res = data;

		if (len < sizeof(*res) || !res->cur_version)
			return NULL;

		ctx = pex_msg_update_recv_ctx_get(res->req_id);
		if (!ctx)
			return NULL;

		if (timestamp)
			*timestamp = be64_to_cpu(res->cur_version);
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

struct pex_hdr *pex_rx_accept(void *data, size_t len, bool ext)
{
	struct pex_hdr *hdr = data;
	uint16_t hdr_len;
	size_t min_size;

	min_size = sizeof(*hdr);
	if (ext)
		min_size += sizeof(struct pex_ext_hdr);

	if (len < min_size)
		return NULL;

	hdr_len = ntohs(hdr->len);
	if (len < min_size + hdr_len)
		return NULL;

	hdr->len = hdr_len;

	return hdr;
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

	if (server) {
		pex_raw_v4_fd = fd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
		if (fd < 0)
			return -1;

		setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));

#ifdef linux
		pex_raw_v6_fd = fd = socket(PF_INET6, SOCK_RAW, IPPROTO_UDP);
		if (fd < 0)
			goto close_raw;

		setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
		setsockopt(fd, IPPROTO_IPV6, IPV6_HDRINCL, &yes, sizeof(yes));
#endif
	}

	pex_urandom = fopen("/dev/urandom", "r");
	if (!pex_urandom)
		goto close_raw;

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

		setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &yes, sizeof(yes));
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
close_raw:
	if (pex_raw_v4_fd >= 0)
		close(pex_raw_v4_fd);
	if (pex_raw_v6_fd >= 0)
		close(pex_raw_v6_fd);
	pex_raw_v4_fd = -1;
	pex_raw_v6_fd = -1;
	return -1;
}

int pex_unix_open(const char *path, pex_recv_control_cb_t cb)
{
	mode_t prev_mask;
	int fd;

	pex_control_cb = cb;
	unlink(path);

	prev_mask = umask(0177);
	fd = usock(USOCK_UDP | USOCK_UNIX | USOCK_SERVER | USOCK_NONBLOCK, path, NULL);
	umask(prev_mask);
	if (fd < 0)
		return -1;

	pex_unix_fd.cb = pex_unix_cb;
	pex_unix_fd.fd = fd;
	uloop_fd_add(&pex_unix_fd, ULOOP_READ);

	return 0;
}

void pex_close(void)
{
	if (pex_raw_v4_fd >= 0)
		close(pex_raw_v4_fd);
	if (pex_raw_v6_fd >= 0)
		close(pex_raw_v6_fd);
	pex_raw_v4_fd = -1;
	pex_raw_v6_fd = -1;

	if (pex_urandom)
		fclose(pex_urandom);

	if (pex_fd.cb) {
		uloop_fd_delete(&pex_fd);
		close(pex_fd.fd);
	}

	if (pex_unix_fd.cb) {
		uloop_fd_delete(&pex_unix_fd);
		close(pex_unix_fd.fd);
	}

	pex_fd.cb = NULL;
	pex_unix_fd.cb = NULL;
	pex_urandom = NULL;
}
