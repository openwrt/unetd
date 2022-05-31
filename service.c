// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <libubox/avl-cmp.h>
#include "unetd.h"

enum {
	SERVICE_ATTR_TYPE,
	SERVICE_ATTR_CONFIG,
	SERVICE_ATTR_MEMBERS,
	__SERVICE_ATTR_MAX
};

static const struct blobmsg_policy service_policy[__SERVICE_ATTR_MAX] = {
	[SERVICE_ATTR_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[SERVICE_ATTR_CONFIG] = { "config", BLOBMSG_TYPE_TABLE },
	[SERVICE_ATTR_MEMBERS] = { "members", BLOBMSG_TYPE_ARRAY },
};

void network_services_free(struct network *net)
{
	vlist_flush_all(&net->services);
}

static int
__service_parse_members(struct network *net, struct network_service *s,
			const char *name)
{
	struct network_group *group;
	struct network_host *host;

	if (name[0] != '@') {
		host = avl_find_element(&net->hosts, name, host, node);

		if (!host)
			return 0;

		if (s)
			s->members[s->n_members++] = host;

		return 1;
	}

	name++;
	group = avl_find_element(&net->groups, name, group, node);
	if (!group)
		return 0;

	if (s) {
		memcpy(&s->members[s->n_members], group->members,
		       group->n_members * sizeof(group->members[0]));
		s->n_members += group->n_members;
	}

	return group->n_members;
}

static int
service_parse_members(struct network *net, struct network_service *s,
		      struct blob_attr *data)
{
	struct blob_attr *cur;
	int rem;
	int n = 0;

	blobmsg_for_each_attr(cur, data, rem)
		n += __service_parse_members(net, s, blobmsg_get_string(cur));

	return n;
}

static void
service_add(struct network *net, struct blob_attr *data)
{
	struct network_service *s;
	struct blob_attr *tb[__SERVICE_ATTR_MAX];
	struct blob_attr *cur, *config;
	const char *name = blobmsg_name(data);
	const char *type = NULL;
	char *name_buf, *type_buf;
	void *config_buf;
	int n_members;

	blobmsg_parse(service_policy, __SERVICE_ATTR_MAX, tb,
		      blobmsg_data(data), blobmsg_len(data));

	if ((cur = tb[SERVICE_ATTR_TYPE]) != NULL)
		type = blobmsg_get_string(cur);

	if (blobmsg_check_array(tb[SERVICE_ATTR_MEMBERS], BLOBMSG_TYPE_STRING) < 0)
		return;

	config = tb[SERVICE_ATTR_CONFIG];

	n_members = service_parse_members(net, NULL, tb[SERVICE_ATTR_MEMBERS]);
	s = calloc_a(sizeof(*s) + n_members * sizeof(s->members[0]),
		     &name_buf, strlen(name) + 1,
		     &type_buf, type ? strlen(type) + 1 : 0,
		     &config_buf, config ? blob_pad_len(config) : 0);

	strcpy(name_buf, name);
	if (type)
		s->type = strcpy(type_buf, type);
	if (config)
		s->config = memcpy(config_buf, config, blob_pad_len(config));

	service_parse_members(net, s, tb[SERVICE_ATTR_MEMBERS]);
	vlist_add(&net->services, &s->node, name_buf);
}

void network_services_add(struct network *net, struct blob_attr *data)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, data, rem)
		service_add(net, cur);
}

static void
service_update(struct vlist_tree *tree, struct vlist_node *node_new,
	       struct vlist_node *node_old)
{
	struct network_service *s_old;

	s_old = container_of_safe(node_old, struct network_service, node);
	if (s_old)
		free(s_old);
}

void network_services_init(struct network *net)
{
	vlist_init(&net->services, avl_strcmp, service_update);
}
