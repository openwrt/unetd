#ifndef PEX_PQC_H
#define PEX_PQC_H

#include <stdint.h>
#include "chacha20.h"
#include "curve25519.h"
#include "pex-msg.h"
#include "sha512.h"
#include "sntrup761.h"

#define PEX_PQC_MAC_LEN		32

struct network;
struct network_peer;

enum pex_pqc_state {
	PEX_PQC_STATE_IDLE,
	PEX_PQC_STATE_WAITING_FOR_M1B,
	PEX_PQC_STATE_WAITING_FOR_M2A,
	PEX_PQC_STATE_WAITING_FOR_M2B,
};

enum pex_pqc_role {
	PEX_PQC_ROLE_NONE,
	PEX_PQC_ROLE_RESPONDER,
	PEX_PQC_ROLE_INITIATOR,
};

struct pex_pqc_ctx {
	enum pex_pqc_role role;
	enum pex_pqc_state state;

	uint8_t dh_key[CURVE25519_KEY_SIZE];

	uint8_t e_sec[SNTRUP761_SEC_SIZE];
	uint8_t e_pub[SNTRUP761_PUB_SIZE];

	uint8_t k1[SNTRUP761_BYTES];
	uint8_t k2[SNTRUP761_BYTES];
	uint8_t k3[SNTRUP761_BYTES];

	uint8_t msg_c1[SNTRUP761_CTEXT_SIZE];
	uint8_t msg_c1_time[8];
	uint8_t msg_c1_mac[PEX_PQC_MAC_LEN];
	uint8_t msg_c1_nonce[CHACHA20_NONCE_SIZE];
	uint8_t msg_e_pub_enc[SNTRUP761_PUB_SIZE];
	uint8_t msg_e_pub_mac[PEX_PQC_MAC_LEN];
	uint8_t msg_e_pub_nonce[CHACHA20_NONCE_SIZE];

	uint8_t resp_c2_enc[SNTRUP761_CTEXT_SIZE];
	uint8_t resp_c2_mac[PEX_PQC_MAC_LEN];
	uint8_t resp_c3_enc[SNTRUP761_CTEXT_SIZE];
	uint8_t resp_c3_mac[PEX_PQC_MAC_LEN];
	uint8_t resp_nonce[CHACHA20_NONCE_SIZE];

	int retransmit_count;
};

struct pex_pqc_m1a {
	uint8_t c1[SNTRUP761_CTEXT_SIZE];
	uint8_t c1_time[8];
	uint8_t c1_mac[PEX_PQC_MAC_LEN];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
};

struct pex_pqc_m1b {
	uint8_t e_pub_enc[SNTRUP761_PUB_SIZE];
	uint8_t e_pub_mac[PEX_PQC_MAC_LEN];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
};

struct pex_pqc_m2 {
	uint8_t c_enc[SNTRUP761_CTEXT_SIZE];
	uint8_t c_mac[PEX_PQC_MAC_LEN];
	uint8_t nonce[CHACHA20_NONCE_SIZE];
};

void pex_pqc_hash_init(void);
void pex_pqc_ctx_init(struct network *net, struct network_peer *peer);
void pex_pqc_recv(struct network *net, struct network_peer *peer,
		  enum pex_opcode opcode, void *data, size_t len);
void pex_pqc_poll(struct network *net, struct network_peer *peer);

#endif /* PEX_PQC_H */
