#ifndef PSK_KEX_H
#define PSK_KEX_H

#include "network.h"
#include "host.h"
#include "stdint.h"
#include "sntrup761.h"

#define MAC_LEN		8

enum psk_kex_state {
	KEX_STATE_IDLE,
	KEX_STATE_WAITING_FOR_STATUS_RESPONSE,
	KEX_STATE_WAITING_FOR_RESPONDER,
};

enum psk_kex_role {
	PSK_KEX_ROLE_NONE,
	PSK_KEX_ROLE_RESPONDER,
	PSK_KEX_ROLE_INITIATOR,
};

struct psk_kex_ctx {
	/* static */
	enum psk_kex_role role;

	/* dynamic */
	enum psk_kex_state state;
	uint8_t e_sec[SNTRUP761_SEC_SIZE];
	uint8_t e_pub[SNTRUP761_PUB_SIZE];

	uint8_t k1[SNTRUP761_BYTES];
	uint8_t k2[SNTRUP761_BYTES];
	uint8_t k3[SNTRUP761_BYTES];
};

struct pex_psk_kex_status {
	uint64_t last_handshake_time;
	bool need_handshake;
};

struct pex_psk_kex_initiator_msg {
	uint8_t c1[SNTRUP761_CTEXT_SIZE];
	uint8_t e_pub_enc[SNTRUP761_PUB_SIZE];
	uint8_t e_pub_mac[MAC_LEN];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
};

struct pex_psk_kex_responder_msg {
	uint8_t c2_enc[SNTRUP761_CTEXT_SIZE];
	uint8_t c3_enc[SNTRUP761_CTEXT_SIZE];
	uint8_t c2_mac[MAC_LEN];
	uint8_t c3_mac[MAC_LEN];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
};

void gen_kex_hash(void);
void init_psk_kex_ctx(struct network *net, struct network_peer *peer);
void psk_kex_recv_msg(struct network *net, struct network_peer *peer, enum pex_opcode opcode, const void *data, size_t len);

#endif /* PSK_KEX_H */
