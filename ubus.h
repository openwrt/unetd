// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_UBUS_H
#define __UNETD_UBUS_H

#ifdef UBUS_SUPPORT
void unetd_ubus_init(void);
void unetd_ubus_notify(const char *type, struct blob_attr *data);
void unetd_ubus_network_notify(struct network *net);
void unetd_ubus_netifd_update(struct blob_attr *data);
void unetd_ubus_netifd_add_route(struct network *net, union network_endpoint *ep);
struct blob_attr *unetd_ubus_get_network_addr_list(const char *name);
#else
static inline void unetd_ubus_init(void)
{
}
static inline void unetd_ubus_notify(const char *type, struct blob_attr *data)
{
}
static inline void unetd_ubus_network_notify(struct network *net)
{
}
static inline void unetd_ubus_netifd_update(struct blob_attr *data)
{
}
static inline void unetd_ubus_netifd_add_route(struct network *net, union network_endpoint *ep)
{
}
static inline struct blob_attr *unetd_ubus_get_network_addr_list(const char *name)
{
	return NULL;
}
#endif

#endif
