// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_PEX_H
#define __UNETD_PEX_H

#include <libubox/uloop.h>

struct network;

struct network_pex {
	struct uloop_fd fd;
};

enum pex_event {
	PEX_EV_HANDSHAKE,
	PEX_EV_ENDPOINT_CHANGE,
	PEX_EV_QUERY,
	PEX_EV_PING,
};

void network_pex_init(struct network *net);
int network_pex_open(struct network *net);
void network_pex_close(struct network *net);

void network_pex_event(struct network *net, struct network_peer *peer,
		       enum pex_event ev);

static inline bool network_pex_active(struct network_pex *pex)
{
	return pex->fd.fd >= 0;
}

#endif
