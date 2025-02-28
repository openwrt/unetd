// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_H
#define __UNETD_H

#include <stdbool.h>

#include <libubox/vlist.h>
#include <libubox/blobmsg.h>
#include <libubox/utils.h>
#ifdef UBUS_SUPPORT
#include <udebug.h>
#endif
#include "utils.h"
#include "siphash.h"
#include "wg.h"
#include "pex-msg.h"
#include "pex.h"
#include "network.h"
#include "host.h"
#include "service.h"
#include "ubus.h"
#include "auth-data.h"
#include "chacha20.h"
#include "token.h"

extern const char *mssfix_path;
extern const char *data_dir;
extern int global_pex_port;
bool unetd_debug_active(void);
void unetd_debug_printf(const char *format, ...);
#ifdef UBUS_SUPPORT
void unetd_udebug_config(struct udebug_ubus *ctx, struct blob_attr *data,
			 bool enabled);
#endif

#define D(format, ...)							\
	do {								\
		unetd_debug_printf("%s(%d) " format "\n",		\
				   __func__, __LINE__, ##__VA_ARGS__);	\
	} while (0)

#define D_NET(net, format, ...)	D("network %s " format, network_name(net), ##__VA_ARGS__)
#define D_HOST(net, host, format, ...) D_NET(net, "host %s " format, network_host_name(host), ##__VA_ARGS__)
#define D_PEER(net, peer, format, ...) D_NET(net, "host %s " format, network_peer_name(peer), ##__VA_ARGS__)
#define D_SERVICE(net, service, format, ...) D_NET(net, "service %s " format, network_service_name(service), ##__VA_ARGS__)

#define UNETD_DATA_DIR "/etc/unetd"
#define UNETD_MSS_BPF_PATH	"/lib/bpf/mss.o"
#define UNETD_MSS_PRIO_BASE	0x130

#define UNETD_DATA_UPDATE_DELAY	(10 * 1000)

#define UNETD_PEX_HOST_ACITVE_TIMEOUT	60

void unetd_write_hosts(void);
int unetd_attach_mssfix(int ifindex, int mtu);

#endif
