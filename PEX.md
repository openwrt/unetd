
# PEX - Peer Endpoint eXchange protocol

## Header:

	struct pex_hdr {
	    uint8_t version;
	    uint8_t opcode;
	    uint16_t len;
	    uint8_t id[8];
	};

- version: always 0 for now
- opcode: message type
- len: payload length
- id: local peer id

All multi-byte integer fields are in big-endian byte order.
Peer identifiers contain the first 8 bytes of the public key

## Message types

### opcode=0: PEX_MSG_HELLO

Payload (single item):

	struct pex_hello {
	    uint16_t flags;
	    uint8_t local_addr[16];
	};

- local_addr: Local IPv4 or IPv6 address used for connecting to the remote endpoint
- flags:
Bit 0: local_addr is an IPv6 address

Sent after any successful handshake.

### opcode=1: PEX_MSG_NOTIFY_PEERS

Used to send information about one or more peers, either proactively, or as a response to PEX_MSG_QUERY

Payload (multiple):

	struct pex_peer_endpoint {
	    uint16_t flags;
	    uint16_t port;
	    uint8_t peer_id[PEX_ID_LEN];
	    uint8_t addr[16];
	};

- port: endpoint port
- addr: IPv4 or IPv6 endpoint address
- peer_id: peer ID
- flags:
Bit 0: addr is an IPv6 address
Bit 1: addr refers to the local network address of the peer

### opcode=2: PEX_MSG_QUERY

Used to ask for the endpoint address of one or more peers. Expects a PEX_MSG_NOTIFY_PEERS response, but only if there is known data about any of the queried peers.

Payload (multiple):

	uint8_t peer_id[8];

For any peer in the payload list that has a known endpoint address, compare the IP address against the endpoint address of the sender of this message.
If the IP address matches, send back the local address of the peer (from the PEX_MSG_HELLO message) instead of the discovered wireguard endpoint address. This helps with establishing a direct connection through double-NAT.

### opcode=3: PEX_MSG_PING

Used to ping a peer (to keep the connection alive).
No payload.

### opcode=4: PEX_MSG_PONG

Response to PEX_MSG_PING.
No payload.

