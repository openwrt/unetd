// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <net/if.h>
#include <libubox/avl-cmp.h>
#include <libubox/utils.h>
#include <libubox/blobmsg_json.h>
#include "unetd.h"
#include "enroll.h"

enum {
	NETDATA_ATTR_CONFIG,
	NETDATA_ATTR_HOSTS,
	NETDATA_ATTR_GROUPS,
	NETDATA_ATTR_SERVICES,
	__NETDATA_ATTR_MAX,
};

static const struct blobmsg_policy netdata_policy[__NETDATA_ATTR_MAX] = {
	[NETDATA_ATTR_CONFIG] = { "config", BLOBMSG_TYPE_TABLE },
	[NETDATA_ATTR_HOSTS] = { "hosts", BLOBMSG_TYPE_TABLE },
	[NETDATA_ATTR_SERVICES] = { "services", BLOBMSG_TYPE_TABLE },
};

enum {
	NETCONF_ATTR_ID,
	NETCONF_ATTR_PORT,
	NETCONF_ATTR_PEX_PORT,
	NETCONF_ATTR_KEEPALIVE,
	NETCONF_ATTR_STUN_SERVERS,
	__NETCONF_ATTR_MAX
};

static const struct blobmsg_policy netconf_policy[__NETCONF_ATTR_MAX] = {
	[NETCONF_ATTR_ID] = { "id", BLOBMSG_TYPE_STRING },
	[NETCONF_ATTR_PORT] = { "port", BLOBMSG_TYPE_INT32 },
	[NETCONF_ATTR_PEX_PORT] = { "peer-exchange-port", BLOBMSG_TYPE_INT32 },
	[NETCONF_ATTR_KEEPALIVE] = { "keepalive", BLOBMSG_TYPE_INT32 },
	[NETCONF_ATTR_STUN_SERVERS] = { "stun-servers", BLOBMSG_TYPE_ARRAY },
};

const struct blobmsg_policy network_policy[__NETWORK_ATTR_MAX] = {
	[NETWORK_ATTR_NAME] = { "name", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_TYPE] = { "type", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_AUTH_KEY] = { "auth_key", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_KEY] = { "key", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_FILE] = { "file", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_DATA] = { "data", BLOBMSG_TYPE_TABLE },
	[NETWORK_ATTR_INTERFACE] = { "interface", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_KEEPALIVE] = { "keepalive", BLOBMSG_TYPE_INT32 },
	[NETWORK_ATTR_DOMAIN] = { "domain", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_UPDATE_CMD] = { "update-cmd", BLOBMSG_TYPE_STRING },
	[NETWORK_ATTR_TUNNELS] = { "tunnels", BLOBMSG_TYPE_TABLE },
	[NETWORK_ATTR_LOCAL_NET] = { "local_network", BLOBMSG_TYPE_ARRAY },
	[NETWORK_ATTR_AUTH_CONNECT] = { "auth_connect", BLOBMSG_TYPE_ARRAY },
	[NETWORK_ATTR_PEER_DATA] = { "peer_data", BLOBMSG_TYPE_ARRAY },
};

AVL_TREE(networks, avl_strcmp, false, NULL);
static struct blob_buf b;

static void network_load_stun_servers(struct network *net, struct blob_attr *data)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, data, rem)
		network_stun_server_add(net, blobmsg_get_string(cur));
}

static void network_load_config_data(struct network *net, struct blob_attr *data)
{
	struct blob_attr *tb[__NETCONF_ATTR_MAX];
	struct blob_attr *cur;
	siphash_key_t key = {};

	blobmsg_parse(netconf_policy, __NETCONF_ATTR_MAX, tb,
		      blobmsg_data(data), blobmsg_len(data));

	if ((cur = tb[NETCONF_ATTR_PORT]) != NULL)
		net->net_config.port = blobmsg_get_u32(cur);
	else
		net->net_config.port = 51820;

	if ((cur = tb[NETCONF_ATTR_PEX_PORT]) != NULL)
		net->net_config.pex_port = blobmsg_get_u32(cur);

	if ((cur = tb[NETCONF_ATTR_ID]) != NULL) {
		const char *id = blobmsg_get_string(cur);
		siphash_to_le64(&net->net_config.addr.network_id, id, strlen(id), &key);
	} else {
		uint32_t port = cpu_to_le32(net->net_config.port);
		siphash_to_le64(&net->net_config.addr.network_id, &port, sizeof(port), &key);
	}

	net->net_config.addr.network_id[0] = 0xfd;
	network_fill_host_addr(&net->net_config.addr, net->config.pubkey);

	if (net->config.keepalive >= 0)
		net->net_config.keepalive = net->config.keepalive;
	else if ((cur = tb[NETCONF_ATTR_KEEPALIVE]) != NULL)
		net->net_config.keepalive = blobmsg_get_u32(cur);
	else
		net->net_config.keepalive = 0;

	if ((cur = tb[NETCONF_ATTR_STUN_SERVERS]) != NULL &&
	    blobmsg_check_array(cur, BLOBMSG_TYPE_STRING) > 0)
		network_load_stun_servers(net, cur);
}

static int network_load_data(struct network *net, struct blob_attr *data)
{
	struct blob_attr *tb[__NETDATA_ATTR_MAX];
	siphash_key_t key = {};

	net->net_config.hash = siphash(data, blob_raw_len(data), &key);
	blobmsg_parse(netdata_policy, __NETDATA_ATTR_MAX, tb,
		      blobmsg_data(data), blobmsg_len(data));

	network_load_config_data(net, tb[NETDATA_ATTR_CONFIG]);
	network_hosts_add(net, tb[NETDATA_ATTR_HOSTS]);
	network_services_add(net, tb[NETDATA_ATTR_SERVICES]);

	return 0;
}

static int network_load_file(struct network *net)
{
	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_file(&b, net->config.file))
		return -1;

	return network_load_data(net, b.head);
}

static int network_load_dynamic(struct network *net)
{
	const char *json = NULL;
	char *fname = NULL;
	struct stat st;
	FILE *f = NULL;
	int ret = -1;

	if (asprintf(&fname, "%s/%s.bin", data_dir, network_name(net)) < 0)
		return -1;

	f = fopen(fname, "r");
	free(fname);

	if (!f) {
		D_NET(net, "failed to open %s/%s.bin\n", data_dir, network_name(net));
		return -1;
	}

	if (fstat(fileno(f), &st) < 0)
		goto out;

	net->net_data_len = st.st_size;
	net->net_data = realloc(net->net_data, net->net_data_len + 1);
	memset(net->net_data + net->net_data_len, 0, 1);
	if (fread(net->net_data, 1, net->net_data_len, f) != net->net_data_len ||
	    unet_auth_data_validate(net->config.auth_key, net->net_data,
				    net->net_data_len, &net->net_data_version, &json)) {
		net->net_data_len = 0;
		goto out;
	}

	fclose(f);
	blob_buf_init(&b, 0);
	if (!blobmsg_add_json_from_string(&b, json)) {
		net->net_data_len = 0;
		return -1;
	}

	return network_load_data(net, b.head);

out:
	fclose(f);
	return ret;
}

int network_save_dynamic(struct network *net)
{
	char *fname = NULL, *fname2;
	size_t len;
	FILE *f;
	int fd, ret;

	if (net->config.type != NETWORK_TYPE_DYNAMIC ||
	    !net->net_data_len)
		return -1;

	if (asprintf(&fname, "%s/%s.bin.XXXXXXXX", data_dir, network_name(net)) < 0)
		return -1;

	fd = mkstemp(fname);
	if (fd < 0)
		goto error;

	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		goto error;
	}

	len = fwrite(net->net_data, 1, net->net_data_len, f);
	fflush(f);
	fdatasync(fd);
	fclose(f);

	if (len != net->net_data_len)
		goto error;

	fname2 = strdup(fname);
	*strrchr(fname2, '.') = 0;
	ret = rename(fname, fname2);
	free(fname2);

	if (ret)
		unlink(fname);
	free(fname);

	return ret;

error:
	free(fname);
	return -1;
}


static void
network_fill_ip(struct blob_buf *buf, int af, union network_addr *addr, int mask)
{
	char *str;
	void *c;

	c = blobmsg_open_table(buf, NULL);

	blobmsg_printf(buf, "mask", "%d", mask);

	str = blobmsg_alloc_string_buffer(buf, "ipaddr", INET6_ADDRSTRLEN);
	inet_ntop(af, addr, str, INET6_ADDRSTRLEN);
	blobmsg_add_string_buffer(buf);

	blobmsg_close_table(buf, c);
}

static void
network_fill_ipaddr_list(struct network_host *host, struct blob_buf *b, bool ipv6)
{
	union network_addr addr = {};
	struct blob_attr *cur;
	void *c;
	int rem;
	int af;

	af = ipv6 ? AF_INET6 : AF_INET;
	blobmsg_for_each_attr(cur, host->peer.ipaddr, rem) {
		const char *str = blobmsg_get_string(cur);

		if (!!strchr(str, ':') != ipv6)
			continue;

		if (inet_pton(af, str, &addr) != 1)
			continue;

		c = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "ipaddr", str);
		blobmsg_add_string(b, "mask", ipv6 ? "128" : "32");
		blobmsg_close_table(b, c);
	}
}

static void
network_fill_ip_settings(struct network *net, struct blob_buf *buf)
{
	struct network_host *host = net->net_config.local_host;
	void *c;

	c = blobmsg_open_array(buf, "ipaddr");
	network_fill_ipaddr_list(host, buf, false);
	blobmsg_close_array(buf, c);

	c = blobmsg_open_array(buf, "ip6addr");
	network_fill_ip(buf, AF_INET6, &host->peer.local_addr, 64);
	network_fill_ipaddr_list(host, buf, true);
	blobmsg_close_array(buf, c);
}

static void
__network_fill_host_subnets(struct network_host *host, struct blob_buf *b, bool ipv6)
{
	union network_addr addr = {};
	struct blob_attr *cur;
	void *c;
	int af;
	int mask;
	int rem;

	af = ipv6 ? AF_INET6 : AF_INET;
	blobmsg_for_each_attr(cur, host->peer.subnet, rem) {
		const char *str = blobmsg_get_string(cur);
		char *buf;

		if (!!strchr(str, ':') != ipv6)
			continue;

		if (network_get_subnet(af, &addr, &mask, str))
			continue;

		c = blobmsg_open_table(b, NULL);

		buf = blobmsg_alloc_string_buffer(b, "target", INET6_ADDRSTRLEN);
		inet_ntop(af, &addr, buf, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(b);

		blobmsg_printf(b, "netmask", "%d", mask);

		blobmsg_close_table(b, c);
	}

	blobmsg_for_each_attr(cur, host->peer.ipaddr, rem) {
		const char *str = blobmsg_get_string(cur);

		if (!!strchr(str, ':') != ipv6)
			continue;

		if (inet_pton(af, str, &addr) != 1)
			continue;

		c = blobmsg_open_table(b, NULL);
		blobmsg_add_string(b, "target", str);
		blobmsg_add_string(b, "netmask", ipv6 ? "128" : "32");
		blobmsg_close_table(b, c);
	}
}

static void
__network_fill_subnets(struct network *net, struct blob_buf *buf, bool ipv6)
{
	struct network_host *host;
	void *c;

	c = blobmsg_open_array(buf, ipv6 ? "routes6": "routes");
	avl_for_each_element(&net->hosts, host, node) {
		if (host == net->net_config.local_host)
			continue;
		__network_fill_host_subnets(host, buf, ipv6);
	}
	blobmsg_close_array(buf, c);
}


static void
network_fill_subnets(struct network *net, struct blob_buf *buf)
{
	__network_fill_subnets(net, buf, false);
	__network_fill_subnets(net, buf, true);
}

static bool
__network_skip_endpoint_route(struct network *net, struct network_host *host,
			      union network_endpoint *ep)
{
	bool ipv6 = ep->sa.sa_family == AF_INET6;
	uint32_t *subnet32, *addr32, mask32;
	union network_addr addr = {};
	struct blob_attr *cur;
	int mask, rem;

	blobmsg_for_each_attr(cur, host->peer.ipaddr, rem) {
		const char *str = blobmsg_get_string(cur);

		if (!!strchr(str, ':') != ipv6)
			continue;

		if (inet_pton(ep->sa.sa_family, str, &addr) != 1)
			continue;

		if (ipv6) {
			if (!memcmp(&addr.in6, &ep->in6.sin6_addr, sizeof(addr.in6)))
				return true;
		} else {
			if (!memcmp(&addr.in, &ep->in.sin_addr, sizeof(addr.in)))
				return true;
		}
	}

	if (ipv6)
		addr32 = (uint32_t *)&ep->in6.sin6_addr;
	else
		addr32 = (uint32_t *)&ep->in.sin_addr;

	subnet32 = (uint32_t *)&addr;
	blobmsg_for_each_attr(cur, host->peer.subnet, rem) {
		const char *str = blobmsg_get_string(cur);
		int i;

		if (!!strchr(str, ':') != ipv6)
			continue;

		if (network_get_subnet(ep->sa.sa_family, &addr, &mask, str))
			continue;

		if (mask <= 1)
			continue;

		for (i = 0; i < (ipv6 ? 4 : 1); i++) {
			int cur_mask = mask > 32 ? 32 : mask;

			if (mask > 32)
				mask -= 32;
			else
				mask = 0;

			mask32 = ~0ULL << (32 - cur_mask);
			if (ntohl(subnet32[i] ^ addr32[i]) & mask32)
				continue;
		}

		return true;
	}

	return false;
}

bool network_skip_endpoint_route(struct network *net, union network_endpoint *ep)
{
	struct network_host *host;

	avl_for_each_element(&net->hosts, host, node)
		if (__network_skip_endpoint_route(net, host, ep))
			return true;

	return false;
}


static void
network_do_update(struct network *net, bool up)
{
	if (!net->net_config.local_host)
		up = false;

	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "action", 0);
	blobmsg_add_string(&b, "ifname", network_name(net));
	blobmsg_add_u8(&b, "link-up", up);

	if (up) {
		network_fill_ip_settings(net, &b);
		network_fill_subnets(net, &b);
	}

	if (debug) {
		char *s = blobmsg_format_json(b.head, true);
		D_NET(net, "update: %s", s);
		free(s);
	}

	if (net->config.update_cmd) {
		const char *argv[] = { net->config.update_cmd, NULL, NULL };
		int pid, stat;

		pid = fork();
		if (pid == 0) {
			argv[1] = blobmsg_format_json(b.head, true);
			execvp(argv[0], (char **)argv);
			exit(1);
		}
		waitpid(pid, &stat, 0);
	}

	if (!net->config.interface)
		return;

	blobmsg_add_string(&b, "interface", net->config.interface);
	unetd_ubus_netifd_update(b.head);
}

static void network_reload(struct uloop_timeout *t)
{
	struct network *net = container_of(t, struct network, reload_timer);

	net->prev_local_host = net->net_config.local_host;

	memset(&net->net_config, 0, sizeof(net->net_config));

	network_stun_free(net);
	network_pex_close(net);
	network_services_free(net);
	network_hosts_update_start(net);
	network_services_update_start(net);

	switch (net->config.type) {
	case NETWORK_TYPE_FILE:
		network_load_file(net);
		break;
	case NETWORK_TYPE_INLINE:
		network_load_data(net, net->config.net_data);
		break;
	case NETWORK_TYPE_DYNAMIC:
		network_load_dynamic(net);
		break;
	}

	network_services_update_done(net);
	network_hosts_update_done(net);
	uloop_timeout_set(&net->connect_timer, 10);

	net->prev_local_host = NULL;

	unetd_write_hosts();
	network_do_update(net, true);
	network_pex_open(net);
	network_stun_start(net);
	unetd_ubus_network_notify(net);
}

void network_soft_reload(struct network *net)
{
	siphash_key_t key = {};
	uint64_t hash;

	if (net->config.type == NETWORK_TYPE_FILE) {
		blob_buf_init(&b, 0);

		if (!blobmsg_add_json_from_file(&b, net->config.file))
			return;

		hash = siphash(b.head, blob_raw_len(b.head), &key);
		if (hash != net->net_config.hash) {
			uloop_timeout_set(&net->reload_timer, 1);
			return;
		}
	}

	network_hosts_reload_dynamic_peers(net);
}

static int network_setup(struct network *net)
{
	if (wg_init_network(net)) {
		fprintf(stderr, "Setup failed for network %s\n", network_name(net));
		return -1;
	}

	net->ifindex = if_nametoindex(network_name(net));
	if (!net->ifindex) {
		fprintf(stderr, "Could not get ifindex for network %s\n", network_name(net));
		return -1;
	}

	return 0;
}

static void network_teardown(struct network *net)
{
	enroll_net_cleanup(net);
	uloop_timeout_cancel(&net->connect_timer);
	uloop_timeout_cancel(&net->reload_timer);
	network_do_update(net, false);
	network_stun_free(net);
	network_pex_close(net);
	network_pex_free(net);
	network_hosts_free(net);
	network_services_free(net);
	wg_cleanup_network(net);
}

static void
network_destroy(struct network *net)
{
	network_teardown(net);
	avl_delete(&networks, &net->node);
	free(net->net_data);
	free(net->config.data);
	free(net);
}

static int
network_set_config(struct network *net, struct blob_attr *config)
{
	struct blob_attr *tb[__NETWORK_ATTR_MAX];
	struct blob_attr *cur;

	if (net->config.data && blob_attr_equal(net->config.data, config))
		goto reload;

	network_teardown(net);

	free(net->config.data);
	memset(&net->config, 0, sizeof(net->config));

	net->config.data = blob_memdup(config);
	blobmsg_parse(network_policy, __NETWORK_ATTR_MAX, tb,
		      blobmsg_data(net->config.data),
		      blobmsg_len(net->config.data));

	if ((cur = tb[NETWORK_ATTR_TYPE]) == NULL ||
	    !strlen(blobmsg_get_string(cur)) ||
	    !strcmp(blobmsg_get_string(cur), "dynamic"))
		net->config.type = NETWORK_TYPE_DYNAMIC;
	else if (!strcmp(blobmsg_get_string(cur), "file"))
		net->config.type = NETWORK_TYPE_FILE;
	else if (!strcmp(blobmsg_get_string(cur), "inline"))
		net->config.type = NETWORK_TYPE_INLINE;
	else
		goto invalid;

	if ((cur = tb[NETWORK_ATTR_KEEPALIVE]) != NULL)
		net->config.keepalive = blobmsg_get_u32(cur);
	else
		net->config.keepalive = -1;

	switch (net->config.type) {
	case NETWORK_TYPE_FILE:
		if ((cur = tb[NETWORK_ATTR_FILE]) != NULL)
			net->config.file = blobmsg_get_string(cur);
		else
			goto invalid;
		break;
	case NETWORK_TYPE_INLINE:
		net->config.net_data = tb[NETWORK_ATTR_DATA];
		if (!net->config.net_data)
			goto invalid;
		break;
	case NETWORK_TYPE_DYNAMIC:
		if ((cur = tb[NETWORK_ATTR_AUTH_KEY]) == NULL)
			goto invalid;

		if (b64_decode(blobmsg_get_string(cur), net->config.auth_key,
			       sizeof(net->config.auth_key)) != sizeof(net->config.auth_key))
			goto invalid;
		break;
	}

	if ((cur = tb[NETWORK_ATTR_INTERFACE]) != NULL &&
	    strlen(blobmsg_get_string(cur)) > 0)
		net->config.interface = blobmsg_get_string(cur);

	if ((cur = tb[NETWORK_ATTR_UPDATE_CMD]) != NULL &&
	    strlen(blobmsg_get_string(cur)) > 0)
		net->config.update_cmd = blobmsg_get_string(cur);

	if ((cur = tb[NETWORK_ATTR_DOMAIN]) != NULL &&
	    strlen(blobmsg_get_string(cur)) > 0)
		net->config.domain = blobmsg_get_string(cur);

	if ((cur = tb[NETWORK_ATTR_TUNNELS]) != NULL)
		net->config.tunnels = cur;

	if ((cur = tb[NETWORK_ATTR_LOCAL_NET]) != NULL &&
	    blobmsg_check_array(cur, BLOBMSG_TYPE_STRING) > 0)
		net->config.local_network = cur;

	if ((cur = tb[NETWORK_ATTR_AUTH_CONNECT]) != NULL &&
	    blobmsg_check_array(cur, BLOBMSG_TYPE_STRING) > 0)
		net->config.auth_connect = cur;

	if ((cur = tb[NETWORK_ATTR_PEER_DATA]) != NULL &&
	    blobmsg_check_array(cur, BLOBMSG_TYPE_STRING) > 0)
		net->config.peer_data = cur;

	if ((cur = tb[NETWORK_ATTR_KEY]) == NULL)
		goto invalid;

	if (b64_decode(blobmsg_get_string(cur), net->config.key, sizeof(net->config.key)) !=
	    sizeof(net->config.key))
		goto invalid;

	curve25519_generate_public(net->config.pubkey, net->config.key);

	if (network_setup(net))
		goto invalid;

reload:
	network_reload(&net->reload_timer);

	return 0;

invalid:
	network_destroy(net);
	return -1;
}

static struct network *
network_alloc(const char *name)
{
	struct network *net;
	char *name_buf;

	net = calloc_a(sizeof(*net), &name_buf, strlen(name) + 1);
	net->node.key = strcpy(name_buf, name);
	net->reload_timer.cb = network_reload;
	avl_insert(&networks, &net->node);

	network_pex_init(net);
	network_stun_init(net);
	network_hosts_init(net);
	network_services_init(net);

	return net;
}

void network_fill_host_addr(union network_addr *addr, uint8_t *pubkey)
{
	siphash_key_t key = {
		.key = {
			get_unaligned_le64(addr->network_id),
			get_unaligned_le64(addr->network_id)
		}
	};

	siphash_to_le64(&addr->host_addr, pubkey, CURVE25519_KEY_SIZE, &key);
}

int unetd_network_add(const char *name, struct blob_attr *config)
{
	struct network *net;

	if (strchr(name, '/'))
		return -1;

	net = avl_find_element(&networks, name, net, node);
	if (!net)
		net = network_alloc(name);

	return network_set_config(net, config);
}

int unetd_network_remove(const char *name)
{
	struct network *net;

	net = avl_find_element(&networks, name, net, node);
	if (!net)
		return -1;

	network_destroy(net);

	return 0;
}

void network_free_all(void)
{
	struct network *net, *tmp;

	avl_for_each_element_safe(&networks, net, node, tmp)
		network_destroy(net);
}
