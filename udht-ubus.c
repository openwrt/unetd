#include <libubus.h>
#include "udht.h"
#include "curve25519.h"

static struct ubus_auto_conn conn;
static struct blob_buf b;

static void
udht_ubus_network_add(struct blob_attr *data, int seq)
{
	static const struct blobmsg_policy net_policy =
		{ "config", BLOBMSG_TYPE_TABLE };
	enum {
		CONFIG_ATTR_AUTH_KEY,
		CONFIG_ATTR_DHT,
		__CONFIG_ATTR_MAX
	};
	static const struct blobmsg_policy policy[__CONFIG_ATTR_MAX] = {
		[CONFIG_ATTR_AUTH_KEY] = { "auth_key", BLOBMSG_TYPE_STRING },
		[CONFIG_ATTR_DHT] = { "dht", BLOBMSG_TYPE_BOOL },
	};
	struct blob_attr *tb[__CONFIG_ATTR_MAX];
	struct blob_attr *config, *cur;
	uint8_t auth_key[CURVE25519_KEY_SIZE];

	blobmsg_parse(&net_policy, 1, &config, blobmsg_data(data), blobmsg_len(data));

	if (!config)
		return;

	blobmsg_parse(policy, __CONFIG_ATTR_MAX, tb, blobmsg_data(config), blobmsg_len(config));
	if ((cur = tb[CONFIG_ATTR_DHT]) == NULL || !blobmsg_get_u8(cur))
		return;

	if ((cur = tb[CONFIG_ATTR_AUTH_KEY]) == NULL ||
	    (b64_decode(blobmsg_get_string(cur), auth_key, CURVE25519_KEY_SIZE) !=
		 CURVE25519_KEY_SIZE))
		return;

	udht_network_add(auth_key, seq);
}


static void
udht_ubus_network_cb(struct ubus_request *req, int type,
		     struct blob_attr *msg)
{
	static const struct blobmsg_policy policy =
		{ "networks", BLOBMSG_TYPE_TABLE };
	struct blob_attr *networks, *cur;
	int *seq = req->priv;
	int rem;

	blobmsg_parse(&policy, 1, &networks, blobmsg_data(msg), blobmsg_len(msg));

	if (!networks)
		return;

	blobmsg_for_each_attr(cur, networks, rem)
		udht_ubus_network_add(cur, *seq);
}

static void
udht_ubus_update_networks(struct ubus_context *ctx)
{
	static int seq;
	uint32_t id;

	seq++;

	if (ubus_lookup_id(ctx, "unetd", &id) ||
	    ubus_invoke(ctx, id, "network_get", b.head, udht_ubus_network_cb, &seq, 5000))
		return;

	udht_network_flush(seq);
}

static int
udht_ubus_unetd_cb(struct ubus_context *ctx, struct ubus_object *obj,
		   struct ubus_request_data *req, const char *method,
		   struct blob_attr *msg)
{
	udht_ubus_update_networks(ctx);

	return 0;
}

static void
udht_ubus_setup_cb(struct uloop_timeout *t)
{
	struct ubus_context *ctx = &conn.ctx;
	uint32_t id;

	if (ubus_lookup_id(ctx, "unetd", &id))
		return;

	/* ensure that unetd's socket is ready by testing if it's reachable over ubus */
	if (ubus_invoke(ctx, id, "network_get", b.head, NULL, NULL, 10000)) {
		uloop_timeout_set(t, 1000);
		return;
	}

	if (udht_reconnect() < 0) {
		uloop_timeout_set(t, 1000);
		return;
	}

	udht_ubus_update_networks(ctx);
}

static struct uloop_timeout setup_timer = {
	.cb = udht_ubus_setup_cb,
};

static bool
udht_ubus_new_obj_cb(struct ubus_context *ctx, struct ubus_subscriber *s,
		     const char *path)
{
	if (!path || strcmp(path, "unetd") != 0)
		return false;

	uloop_timeout_set(&setup_timer, 100);
	return true;
}

static struct ubus_subscriber sub = {
	.cb = udht_ubus_unetd_cb,
	.new_obj_cb = udht_ubus_new_obj_cb,
};

static void
ubus_connect_handler(struct ubus_context *ctx)
{
	ubus_register_subscriber(ctx, &sub);
}

void udht_ubus_init(void)
{
	blob_buf_init(&b, 0);
	conn.cb = ubus_connect_handler;
	ubus_auto_connect(&conn);
}
