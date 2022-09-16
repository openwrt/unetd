// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_UBUS_H
#define __UNETD_UBUS_H

#ifdef UBUS_SUPPORT
void unetd_ubus_init(void);
void unetd_ubus_notify(struct network *net);
void unetd_ubus_netifd_update(struct blob_attr *data);
void unetd_ubus_netifd_add_route(struct network *net, union network_endpoint *ep);
#else
static inline void unetd_ubus_init(void)
{
}
static inline void unetd_ubus_notify(struct network *net)
{
}
static inline void unetd_ubus_netifd_update(struct blob_attr *data)
{
}
static inline void unetd_ubus_netifd_add_route(struct network *net, union network_endpoint *ep)
{
}
#endif

#endif
