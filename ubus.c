// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <libubus.h>
#include "unetd.h"

static struct ubus_auto_conn conn;
static struct blob_buf b;

static int
ubus_network_add(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *name;

	blobmsg_parse(&network_policy[NETWORK_ATTR_NAME], 1, &name,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!name)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (unetd_network_add(blobmsg_get_string(name), msg))
		return UBUS_STATUS_INVALID_ARGUMENT;

	return 0;
}


static int
ubus_network_del(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *name;

	blobmsg_parse(&network_policy[NETWORK_ATTR_NAME], 1, &name,
		      blobmsg_data(msg), blobmsg_len(msg));

	if (!name)
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (unetd_network_remove(blobmsg_get_string(name)))
		return UBUS_STATUS_NOT_FOUND;

	return 0;
}

static void
__network_dump(struct blob_buf *buf, struct network *net)
{
	struct network_host *local = net->net_config.local_host;
	struct network_peer *peer;
	void *c, *p;
	char *str;

	blobmsg_add_field(buf, BLOBMSG_TYPE_TABLE, "config",
			  blobmsg_data(net->config.data),
			  blobmsg_len(net->config.data));

	if (local)
		blobmsg_add_string(buf, "local_host", network_host_name(local));

	c = blobmsg_open_table(buf, "peers");
	vlist_for_each_element(&net->peers, peer, node) {
		union network_endpoint *ep = &peer->state.endpoint;
		void *addr;
		int len;

		p = blobmsg_open_table(buf, network_peer_name(peer));
		blobmsg_add_u8(buf, "connected", peer->state.connected);
		if (peer->state.connected) {
			str = blobmsg_alloc_string_buffer(buf, "endpoint",
							  INET6_ADDRSTRLEN + 7);
			addr = network_endpoint_addr(ep, &len);
			inet_ntop(ep->sa.sa_family, addr, str, INET6_ADDRSTRLEN);
			len = strlen(str);
			snprintf(str + len, INET6_ADDRSTRLEN + 7 - len, ":%d",
				 ntohs(ep->in.sin_port));
			blobmsg_add_string_buffer(buf);
		}

		blobmsg_close_table(buf, p);
	}
	blobmsg_close_table(buf, c);
}

static int
ubus_network_get(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *name;
	struct network *net;
	void *c, *n;

	blobmsg_parse(&network_policy[NETWORK_ATTR_NAME], 1, &name,
		      blobmsg_data(msg), blobmsg_len(msg));

	blob_buf_init(&b, 0);
	if (name) {
		net = avl_find_element(&networks, blobmsg_get_string(name), net, node);
		if (!net)
			return UBUS_STATUS_NOT_FOUND;

		__network_dump(&b, net);
	} else {
		c = blobmsg_open_table(&b, "networks");
		avl_for_each_element(&networks, net, node) {
			n = blobmsg_open_table(&b, network_name(net));
			__network_dump(&b, net);
			blobmsg_close_table(&b, n);
		}
		blobmsg_close_table(&b, c);
	}

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	SERVICE_ATTR_NETWORK,
	SERVICE_ATTR_NAME,
	__SERVICE_ATTR_MAX
};

static const struct blobmsg_policy service_policy[__SERVICE_ATTR_MAX] = {
	[SERVICE_ATTR_NETWORK] = { "network", BLOBMSG_TYPE_STRING },
	[SERVICE_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
};


static void
ubus_service_get_network_members(struct blob_buf *b, struct network *n,
				 const char *name)
{
	struct network_service *s;
	int i;

	s = vlist_find(&n->services, name, s, node);
	if (!s)
		return;

	for (i = 0; i < s->n_members; i++) {
		struct network_host *host = s->members[i];
		char *name;

		name = blobmsg_alloc_string_buffer(b, NULL, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &host->peer.local_addr.in6, name, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(b);
	}
}


static int
ubus_service_get(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	struct blob_attr *tb[__SERVICE_ATTR_MAX];
	struct blob_attr *cur;
	struct network *n = NULL;
	const char *name;
	void *c;

	blobmsg_parse(service_policy, __SERVICE_ATTR_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[SERVICE_ATTR_NAME]) != NULL)
		name = blobmsg_get_string(cur);
	else
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((cur = tb[SERVICE_ATTR_NETWORK]) != NULL) {
		n = avl_find_element(&networks, blobmsg_get_string(cur), n, node);
		if (!n)
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	blob_buf_init(&b, 0);

	c = blobmsg_open_array(&b, "hosts");
	if (n) {
		ubus_service_get_network_members(&b, n, name);
	} else {
		avl_for_each_element(&networks, n, node)
			ubus_service_get_network_members(&b, n, name);
	}
	blobmsg_close_array(&b, c);
	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
    CONNECT_ATTR_NAME,
    CONNECT_ATTR_ADDRESS,
    CONNECT_ATTR_TIMEOUT,
    __CONNECT_ATTR_MAX
};

static const struct blobmsg_policy connect_policy[__CONNECT_ATTR_MAX] = {
	[CONNECT_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[CONNECT_ATTR_ADDRESS] = { "address", BLOBMSG_TYPE_STRING },
	[CONNECT_ATTR_TIMEOUT] = { "timeout", BLOBMSG_TYPE_INT32 },
};

static int
ubus_network_connect(struct ubus_context *ctx, struct ubus_object *obj,
		     struct ubus_request_data *req, const char *method,
		     struct blob_attr *msg)
{
	struct blob_attr *tb[__CONNECT_ATTR_MAX];
	union network_endpoint ep = {};
	struct blob_attr *cur;
	struct network *net;
	unsigned int timeout;
	const char *name;

	blobmsg_parse(connect_policy, __CONNECT_ATTR_MAX, tb,
		      blobmsg_data(msg), blobmsg_len(msg));

	if ((cur = tb[CONNECT_ATTR_NAME]) != NULL)
		name = blobmsg_get_string(cur);
	else
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((cur = tb[CONNECT_ATTR_TIMEOUT]) != NULL)
		timeout = blobmsg_get_u32(cur);
	else
		return UBUS_STATUS_INVALID_ARGUMENT;

	if ((cur = tb[CONNECT_ATTR_ADDRESS]) == NULL ||
	    network_get_endpoint(&ep, AF_UNSPEC, blobmsg_get_string(cur), UNETD_GLOBAL_PEX_PORT, 0) < 0 ||
	    !ep.in.sin_port)
		return UBUS_STATUS_INVALID_ARGUMENT;

	net = avl_find_element(&networks, name, net, node);
	if (!net)
		return UBUS_STATUS_NOT_FOUND;

	if (net->config.type != NETWORK_TYPE_DYNAMIC)
		return UBUS_STATUS_INVALID_ARGUMENT;

	network_pex_create_host(net, &ep, timeout);

	return 0;
}

static int
ubus_reload(struct ubus_context *ctx, struct ubus_object *obj,
	    struct ubus_request_data *req, const char *method,
	    struct blob_attr *msg)
{
	struct network *net;

	avl_for_each_element(&networks, net, node)
		network_soft_reload(net);

	return 0;
}


static const struct ubus_method unetd_methods[] = {
	UBUS_METHOD("network_add", ubus_network_add, network_policy),
	UBUS_METHOD_MASK("network_del", ubus_network_del, network_policy,
			 (1 << NETWORK_ATTR_NAME)),
	UBUS_METHOD_MASK("network_get", ubus_network_get, network_policy,
			 (1 << NETWORK_ATTR_NAME)),
	UBUS_METHOD("network_connect", ubus_network_connect, connect_policy),
	UBUS_METHOD_NOARG("reload", ubus_reload),
	UBUS_METHOD("service_get", ubus_service_get, service_policy),
};

static struct ubus_object_type unetd_object_type =
	UBUS_OBJECT_TYPE("unetd", unetd_methods);

static struct ubus_object unetd_object = {
	.name = "unetd",
	.type = &unetd_object_type,
	.methods = unetd_methods,
	.n_methods = ARRAY_SIZE(unetd_methods),
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	int ret;

	ret = ubus_add_object(ctx, &unetd_object);
	if (ret)
		fprintf(stderr, "Failed to add object: %s\n", ubus_strerror(ret));
}

static void unetd_ubus_procd_update(void)
{
	void *data, *firewall, *rule;
	struct network *net;
	uint32_t id;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "name", "unetd");

	data = blobmsg_open_table(&b, "data");
	firewall = blobmsg_open_array(&b, "firewall");

	avl_for_each_element(&networks, net, node) {
		if (!net->net_config.local_host || !net->config.interface)
			continue;

		rule = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "type", "rule");
		blobmsg_add_string(&b, "proto", "udp");
		blobmsg_add_string(&b, "src", "*");
		blobmsg_add_u32(&b, "dest_port", net->net_config.port);
		blobmsg_close_table(&b, rule);

		rule = blobmsg_open_table(&b, NULL);
		blobmsg_add_string(&b, "type", "rule");
		blobmsg_add_string(&b, "proto", "udp");
		blobmsg_add_string(&b, "src", "*");
		blobmsg_add_u32(&b, "dest_port", net->net_config.pex_port);
		blobmsg_close_table(&b, rule);
	}

	blobmsg_close_table(&b, firewall);
	blobmsg_close_table(&b, data);

	if (ubus_lookup_id(&conn.ctx, "service", &id))
		return;

	ubus_invoke(&conn.ctx, id, "set", b.head, NULL, NULL, -1);
}

void unetd_ubus_network_notify(struct network *net)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "network", network_name(net));
	ubus_notify(&conn.ctx, &unetd_object, "network_update", b.head, -1);
	unetd_ubus_procd_update();
}

void unetd_ubus_netifd_update(struct blob_attr *data)
{
	uint32_t id;

	if (ubus_lookup_id(&conn.ctx, "network.interface", &id))
		return;

	ubus_invoke(&conn.ctx, id, "notify_proto", data, NULL, NULL, 5000);
}

void unetd_ubus_netifd_add_route(struct network *net, union network_endpoint *ep)
{
	uint32_t id;
	void *addr;
	char *buf;

	if (!net->config.interface)
		return;

	if (ubus_lookup_id(&conn.ctx, "network", &id))
		return;

	blob_buf_init(&b, 0);

	if (ep->in.sin_family == AF_INET6)
		addr = &ep->in6.sin6_addr;
	else
		addr = &ep->in.sin_addr;

	blobmsg_add_u8(&b, "v6", ep->in.sin_family == AF_INET6);
	buf = blobmsg_alloc_string_buffer(&b, "target", INET6_ADDRSTRLEN);
	inet_ntop(ep->in.sin_family, addr, buf, INET6_ADDRSTRLEN);
	blobmsg_add_string_buffer(&b);
	blobmsg_add_string(&b, "interface", net->config.interface);
	blobmsg_add_u8(&b, "exclude", true);

	ubus_invoke(&conn.ctx, id, "add_host_route", b.head, NULL, NULL, -1);
}

void unetd_ubus_init(void)
{
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}
