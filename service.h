// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_SERVICE_H
#define __UNETD_SERVICE_H

struct network_service {
	struct avl_node node;

	const char *type;

	int n_members;
	struct network_host *members[];
};

void network_services_init(struct network *net);
void network_services_free(struct network *net);
void network_services_add(struct network *net, struct blob_attr *data);

#endif
