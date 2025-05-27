// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022-2024 Felix Fietkau <nbd@nbd.name>
 */
#include <arpa/inet.h>
#include <libubus.h>
#include <time.h>
#include "unetd.h"
#include "enroll.h"

static struct ubus_auto_conn conn;
static struct ubus_subscriber sub;
static struct blob_buf b;
static struct udebug_ubus udebug;

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
	struct network_service *s;
	struct network_peer *peer;
	void *c, *p, *m;
	char *str;

	c = blobmsg_open_table(buf, "config");
	network_get_config(net, buf);
	blobmsg_close_table(buf, c);

	if (local) {
		blobmsg_add_string(buf, "local_host", network_host_name(local));

		str = blobmsg_alloc_string_buffer(buf, "local_address", INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &local->peer.local_addr.in6, str, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(buf);
	} else {
		if (net->net_data_len)
			blobmsg_add_u8(buf, "no_local_host", true);
	}

	if (net->update_refused)
		blobmsg_add_u32(buf, "update_refused", net->update_refused);

	c = blobmsg_open_table(buf, "peers");
	vlist_for_each_element(&net->peers, peer, node) {
		union network_endpoint *ep = &peer->state.endpoint;
		void *addr;
		int len;

		p = blobmsg_open_table(buf, network_peer_name(peer));

		str = blobmsg_alloc_string_buffer(buf, "address", INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &peer->local_addr.in6, str, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(buf);

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

			blobmsg_add_u64(buf, "rx_bytes", peer->state.rx_bytes);
			blobmsg_add_u64(buf, "tx_bytes", peer->state.tx_bytes);
			blobmsg_add_u32(buf, "idle", peer->state.idle);
			blobmsg_add_u32(buf, "last_handshake_sec", peer->state.last_handshake_diff);
		}

		blobmsg_close_table(buf, p);
	}
	blobmsg_close_table(buf, c);


	c = blobmsg_open_table(buf, "services");
	vlist_for_each_element(&net->services, s, node) {
		p = blobmsg_open_table(buf, network_service_name(s));

		if (s->type)
			blobmsg_add_string(buf, "type", s->type);

		m = blobmsg_open_array(buf, "members");
		for (size_t i = 0; i < s->n_members; i++)
			blobmsg_add_string(buf, NULL, network_host_name(s->members[i]));
		blobmsg_close_array(buf, m);

		if (s->config)
			blobmsg_add_blob(buf, s->config);
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

static int
ubus_enroll_start(struct ubus_context *ctx, struct ubus_object *obj,
		  struct ubus_request_data *req, const char *method,
		  struct blob_attr *msg)
{
	return enroll_start(msg);
}

static int
ubus_enroll_stop(struct ubus_context *ctx, struct ubus_object *obj,
		 struct ubus_request_data *req, const char *method,
		 struct blob_attr *msg)
{
	enroll_stop();
	return 0;
}

enum {
	ENROLL_PEER_ATTR_ID,
	ENROLL_PEER_ATTR_SESSION,
	ENROLL_PEER_ATTR_INFO,
	__ENROLL_PEER_ATTR_MAX,
};

static const struct blobmsg_policy enroll_peer_policy[__ENROLL_PEER_ATTR_MAX] = {
	[ENROLL_PEER_ATTR_ID] = { "id", BLOBMSG_TYPE_STRING },
	[ENROLL_PEER_ATTR_SESSION] = { "session", BLOBMSG_TYPE_STRING },
	[ENROLL_PEER_ATTR_INFO] = { "info", BLOBMSG_TYPE_TABLE },
};

struct enroll_peer_select {
	uint8_t id[CURVE25519_KEY_SIZE];
	uint32_t session;
	bool has_session, has_id;
};

static int
ubus_enroll_parse(struct enroll_peer_select *sel, struct blob_attr **tb)
{
	struct blob_attr *cur;

	if ((cur = tb[ENROLL_PEER_ATTR_ID]) != NULL) {
		char *str = blobmsg_get_string(cur);

		if (b64_decode(str, sel->id, sizeof(sel->id)) != CURVE25519_KEY_SIZE)
			return -1;

		sel->has_id = true;
	}

	if ((cur = tb[ENROLL_PEER_ATTR_SESSION]) != NULL) {
		char *str = blobmsg_get_string(cur);
		uint32_t id;
		char *err;

		id = strtoul(str, &err, 16);
		if (*err)
			return -1;

		sel->session = cpu_to_be32(id);
		sel->has_session = true;
	}

	return 0;
}

static bool
ubus_enroll_match(struct enroll_peer_select *sel, struct enroll_peer *peer)
{
	if (sel->has_id &&
	    memcmp(peer->pubkey, sel->id, sizeof(sel->id)) != 0)
		return false;
	if (sel->has_session &&
	    memcmp(peer->session_id, &sel->session, sizeof(sel->session)) != 0)
		return false;
	return true;
}

static int
ubus_enroll_status(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__ENROLL_PEER_ATTR_MAX];
	struct enroll_state *state = enroll_state();
	struct enroll_peer_select sel = {};
	struct enroll_peer *peer;
	void *a, *c;

	if (!state)
		return UBUS_STATUS_NO_DATA;

	blobmsg_parse_attr(enroll_peer_policy, __ENROLL_PEER_ATTR_MAX, tb, msg);
	if (ubus_enroll_parse(&sel, tb))
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);

	a = blobmsg_open_array(&b, "peers");
	avl_for_each_element(&state->peers, peer, node) {
		if (!ubus_enroll_match(&sel, peer))
			continue;

		c = blobmsg_open_table(&b, NULL);
		enroll_peer_info(&b, peer);
		blobmsg_close_table(&b, c);
	}
	blobmsg_close_array(&b, a);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

static int
ubus_enroll_accept(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	struct blob_attr *tb[__ENROLL_PEER_ATTR_MAX];
	struct enroll_state *state = enroll_state();
	struct enroll_peer *peer = NULL, *cur;
	struct enroll_peer_select sel = {};

	if (!state)
		return UBUS_STATUS_NO_DATA;

	blobmsg_parse_attr(enroll_peer_policy, __ENROLL_PEER_ATTR_MAX, tb, msg);
	if (ubus_enroll_parse(&sel, tb))
		return UBUS_STATUS_INVALID_ARGUMENT;

	if (!sel.has_id && !sel.has_session)
		return UBUS_STATUS_INVALID_ARGUMENT;

	avl_for_each_element(&state->peers, cur, node) {
		if (!ubus_enroll_match(&sel, cur))
			continue;
		if (peer)
			return UBUS_STATUS_NOT_FOUND;
		peer = cur;
	}

	if (!peer)
		return UBUS_STATUS_NOT_FOUND;

	enroll_peer_accept(peer, tb[ENROLL_PEER_ATTR_INFO]);

	return 0;
}

enum {
	TOKEN_CREATE_ATTR_NETWORK,
	TOKEN_CREATE_ATTR_TARGET,
	TOKEN_CREATE_ATTR_SERVICE,
	TOKEN_CREATE_ATTR_DATA,
	__TOKEN_CREATE_ATTR_MAX,
};

static const struct blobmsg_policy token_create_policy[__TOKEN_CREATE_ATTR_MAX] = {
	[TOKEN_CREATE_ATTR_NETWORK] = { "network", BLOBMSG_TYPE_STRING },
	[TOKEN_CREATE_ATTR_TARGET] = { "target", BLOBMSG_TYPE_STRING },
	[TOKEN_CREATE_ATTR_SERVICE] = { "service", BLOBMSG_TYPE_STRING },
	[TOKEN_CREATE_ATTR_DATA] = { "data", BLOBMSG_TYPE_TABLE },
};

static int
ubus_token_create(struct ubus_context *ctx, struct ubus_object *obj,
	       struct ubus_request_data *req, const char *method,
	       struct blob_attr *msg)
{
	struct blob_attr *tb[__TOKEN_CREATE_ATTR_MAX], *cur;
	struct network_host *target = NULL;
	struct network *net = NULL;
	const char *service = NULL;
	char *str_buf;
	void *token;
	size_t len;

	blobmsg_parse_attr(token_create_policy, __TOKEN_CREATE_ATTR_MAX, tb, msg);

	if ((cur = tb[TOKEN_CREATE_ATTR_NETWORK]) != NULL)
		net = avl_find_element(&networks, blobmsg_get_string(cur), net, node);
	else
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (!net)
		return UBUS_STATUS_NOT_FOUND;

	if ((cur = tb[TOKEN_CREATE_ATTR_TARGET]) != NULL)
		target = avl_find_element(&net->hosts, blobmsg_get_string(cur), target, node);
	else
		return UBUS_STATUS_INVALID_ARGUMENT;
	if (!target)
		return UBUS_STATUS_NOT_FOUND;

	blob_buf_init(&b, 0);
	blobmsg_add_u64(&b, "created", time(NULL));
	if (req->acl.user)
		blobmsg_add_string(&b, "user", req->acl.user);
	if (req->acl.group)
		blobmsg_add_string(&b, "group", req->acl.group);
	if ((cur = tb[TOKEN_CREATE_ATTR_SERVICE]) != NULL) {
		service = blobmsg_get_string(cur);
		blobmsg_add_blob(&b, cur);
	}
	if ((cur = tb[TOKEN_CREATE_ATTR_DATA]) != NULL)
		blobmsg_add_blob(&b, cur);

	token = token_create(net, target, service, b.head, &len);
	if (!token)
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);
	str_buf = blobmsg_alloc_string_buffer(&b, "token", B64_ENCODE_LEN(len));
	b64_encode(token, len, str_buf, B64_ENCODE_LEN(len));
	blobmsg_add_string_buffer(&b);

	ubus_send_reply(ctx, req, b.head);

	return 0;
}

enum {
	TOKEN_PARSE_ATTR_TOKEN,
	__TOKEN_PARSE_ATTR_MAX,
};

static const struct blobmsg_policy token_parse_policy[__TOKEN_PARSE_ATTR_MAX] = {
	[TOKEN_PARSE_ATTR_TOKEN] = { "token", BLOBMSG_TYPE_STRING }
};

static int
ubus_token_parse(struct ubus_context *ctx, struct ubus_object *obj,
	       struct ubus_request_data *req, const char *method,
	       struct blob_attr *msg)
{
	struct blob_attr *tb[__TOKEN_PARSE_ATTR_MAX], *cur;
	const char *token;

	blobmsg_parse_attr(token_parse_policy, __TOKEN_PARSE_ATTR_MAX, tb, msg);

	if ((cur = tb[TOKEN_PARSE_ATTR_TOKEN]) != NULL)
		token = blobmsg_get_string(cur);
	else
		return UBUS_STATUS_INVALID_ARGUMENT;

	blob_buf_init(&b, 0);
	if (!token_parse(&b, token))
		return UBUS_STATUS_INVALID_ARGUMENT;

	ubus_send_reply(ctx, req, b.head);

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
	UBUS_METHOD("enroll_start", ubus_enroll_start, enroll_start_policy),
	UBUS_METHOD_MASK("enroll_status", ubus_enroll_status, enroll_peer_policy,
			(1 << ENROLL_PEER_ATTR_ID) |
			(1 << ENROLL_PEER_ATTR_SESSION)),
	UBUS_METHOD("enroll_accept", ubus_enroll_accept, enroll_peer_policy),
	UBUS_METHOD_NOARG("enroll_stop", ubus_enroll_stop),
	UBUS_METHOD("token_create", ubus_token_create, token_create_policy),
	UBUS_METHOD("token_parse", ubus_token_parse, token_parse_policy),
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

	udebug_ubus_init(&udebug, ctx, "unetd", unetd_udebug_config);
	ubus_register_subscriber(ctx, &sub);
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

void unetd_ubus_notify(const char *type, struct blob_attr *data)
{
	ubus_notify(&conn.ctx, &unetd_object, type, data, -1);
}

void unetd_ubus_network_notify(struct network *net)
{
	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "network", network_name(net));
	unetd_ubus_notify("network_update", b.head);
	unetd_ubus_procd_update();
}

void unetd_ubus_netifd_update(struct blob_attr *data)
{
	uint32_t id;

	if (ubus_lookup_id(&conn.ctx, "network.interface", &id))
		return;

	ubus_invoke(&conn.ctx, id, "notify_proto", data, NULL, NULL, 5000);
}

static void
ubus_network_status_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	static const struct blobmsg_policy policy =
		{ "ipv4-address", BLOBMSG_TYPE_ARRAY };
	struct blob_attr *attr, *cur;
	size_t rem;

	blobmsg_parse_attr(&policy, 1, &attr, msg);
	if (!attr)
		return;

	if (blobmsg_check_array(attr, BLOBMSG_TYPE_TABLE) < 0)
		return;

	blobmsg_for_each_attr(cur, attr, rem)
		blobmsg_add_blob(&b, cur);
}

struct blob_attr *unetd_ubus_get_network_addr_list(const char *name)
{
	char *objname;
	uint32_t id;
	size_t len;

	if (strlen(name) > 64)
		return NULL;

	len = sizeof("network.interface.") + strlen(name) + 1;
	objname = alloca(len);
	snprintf(objname, len, "network.interface.%s", name);

	if (ubus_lookup_id(&conn.ctx, objname, &id))
		return NULL;

	blob_buf_init(&b, 0);
	ubus_invoke(&conn.ctx, id, "status", b.head, ubus_network_status_cb, NULL, 10000);

	return b.head;
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

static int
unetd_netifd_sub_cb(struct ubus_context *ctx, struct ubus_object *obj,
		    struct ubus_request_data *req,
		    const char *method, struct blob_attr *msg)
{
	network_pex_reload();
	return 0;
}

static bool
unetd_new_object_sub_cb(struct ubus_context *ctx, struct ubus_subscriber *sub, const char *path)
{
	return path && !strcmp(path, "network.interface");
}

void unetd_ubus_init(void)
{
	sub.cb = unetd_netifd_sub_cb;
	sub.new_obj_cb = unetd_new_object_sub_cb;
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}
