// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_SERVICE_H
#define __UNETD_SERVICE_H

struct vxlan_tunnel;
struct service_ops;

struct network_service {
	struct vlist_node node;

	struct blob_attr *config;

	const char *type;

	const struct service_ops *ops;
	union {
		struct vxlan_tunnel *vxlan;
		void *priv;
	};

	int n_members;
	struct network_host *members[];
};

struct service_ops {
	void (*init)(struct network *net,
		     struct network_service *s_new,
		     struct network_service *s_old);
	void (*peer_update)(struct network *net, struct network_service *s,
			    struct network_peer *peer);
	void (*free)(struct network *net, struct network_service *s);
};

extern const struct service_ops vxlan_ops;

static inline const char *
network_service_name(struct network_service *s)
{
	return s->node.avl.key;
}

void network_services_init(struct network *net);
void network_services_free(struct network *net);
void network_services_add(struct network *net, struct blob_attr *data);
void network_services_peer_update(struct network *net, struct network_peer *peer);

static inline void network_services_update_start(struct network *net)
{
	vlist_update(&net->services);
}

static inline void network_services_update_done(struct network *net)
{
	vlist_flush(&net->services);
}

#endif
