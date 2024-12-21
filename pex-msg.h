#ifndef __PEX_MSG_H
#define __PEX_MSG_H

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include "curve25519.h"
#include "siphash.h"
#include "utils.h"

#define UNETD_GLOBAL_PEX_PORT		51819
#define PEX_BUF_SIZE			1024
#define PEX_RX_BUF_SIZE			16384
#define UNETD_NET_DATA_SIZE_MAX		(128 * 1024)

enum pex_opcode {
	PEX_MSG_HELLO,
	PEX_MSG_NOTIFY_PEERS,
	PEX_MSG_QUERY,
	PEX_MSG_PING,
	PEX_MSG_PONG,
	PEX_MSG_UPDATE_REQUEST,
	PEX_MSG_UPDATE_RESPONSE,
	PEX_MSG_UPDATE_RESPONSE_DATA,
	PEX_MSG_UPDATE_RESPONSE_NO_DATA,
	PEX_MSG_ENDPOINT_NOTIFY,
	PEX_MSG_ENDPOINT_PORT_NOTIFY,
	PEX_MSG_ENROLL,
};

#define PEX_ID_LEN		8

struct pex_hdr {
	uint8_t version;
	uint8_t opcode;
	uint16_t len;
	uint8_t id[PEX_ID_LEN];
};

struct pex_ext_hdr {
	uint64_t nonce;
	uint8_t auth_id[PEX_ID_LEN];
};

#define PEER_EP_F_IPV6		(1 << 0)
#define PEER_EP_F_LOCAL		(1 << 1)

struct pex_peer_endpoint {
	uint16_t flags;
	uint16_t port;
	uint8_t peer_id[PEX_ID_LEN];
	uint8_t addr[16];
};

struct pex_hello {
	uint16_t flags;
	uint8_t local_addr[16];
};

struct pex_update_request {
	uint64_t req_id; /* must be first */
	uint64_t cur_version;
};

struct pex_update_response {
	uint64_t req_id; /* must be first */
	uint32_t data_len;
	uint8_t e_key[CURVE25519_KEY_SIZE];
};

struct pex_update_response_data {
	uint64_t req_id; /* must be first */
	uint32_t offset;
};

struct pex_update_response_no_data {
	uint64_t req_id; /* must be first */
	uint64_t cur_version;
};

struct pex_endpoint_port_notify {
	uint16_t port;
};

struct pex_msg_update_send_ctx {
	const uint8_t *pubkey;
	const uint8_t *auth_key;
	uint64_t req_id;
	bool ext;

	void *data;
	void *cur;
	int rem;
};

struct pex_msg_local_control {
	int msg_type;
	uint8_t auth_id[PEX_ID_LEN];
	union network_endpoint ep;
	int timeout;
};

struct pex_hdr *pex_rx_accept(void *data, size_t len, bool ext);

typedef void (*pex_recv_cb_t)(void *data, size_t len, struct sockaddr_in6 *addr);
typedef void (*pex_recv_control_cb_t)(struct pex_msg_local_control *msg, int len);

int pex_open(void *addr, size_t addr_len, pex_recv_cb_t cb, bool server);
int pex_unix_open(const char *path, pex_recv_control_cb_t cb);
void pex_close(void);

int pex_socket(void);
int pex_raw_socket(int family);
uint64_t pex_network_hash(const uint8_t *auth_key, uint64_t req_id);
struct pex_hdr *__pex_msg_init(const uint8_t *pubkey, uint8_t opcode);
struct pex_hdr *__pex_msg_init_ext(const uint8_t *pubkey, const uint8_t *auth_key,
				   uint8_t opcode, bool ext);
int __pex_msg_send(int fd, const void *addr, void *ip_hdr, size_t ip_hdrlen);
void *pex_msg_append(size_t len);
void *pex_msg_tail(void);

struct pex_update_request *
pex_msg_update_request_init(const uint8_t *pubkey, const uint8_t *priv_key,
			    const uint8_t *auth_key, union network_endpoint *addr,
			    uint64_t cur_version, bool ext);
void *pex_msg_update_response_recv(const void *data, int len, enum pex_opcode op,
				   int *data_len, uint64_t *timestamp);

void pex_msg_update_response_init(struct pex_msg_update_send_ctx *ctx,
				  const uint8_t *pubkey, const uint8_t *auth_key,
				  const uint8_t *peer_key, bool ext,
				  struct pex_update_request *req,
				  const void *data, int len);
bool pex_msg_update_response_continue(struct pex_msg_update_send_ctx *ctx);

#endif
