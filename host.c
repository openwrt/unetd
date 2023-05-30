// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <libubox/avl-cmp.h>
#include <libubox/blobmsg_json.h>
#include "unetd.h"

static LIST_HEAD(old_hosts);
static struct blob_buf b;

static int avl_key_cmp(const void *k1, const void *k2, void *ptr)
{
	return memcmp(k1, k2, CURVE25519_KEY_SIZE);
}

static bool
network_peer_equal(struct network_peer *p1, struct network_peer *p2)
{
	return !memcmp(&p1->local_addr, &p2->local_addr, sizeof(p1->local_addr)) &&
	       blob_attr_equal(p1->ipaddr, p2->ipaddr) &&
	       blob_attr_equal(p1->subnet, p2->subnet) &&
	       p1->port == p2->port;
}

static void
network_peer_update(struct vlist_tree *tree,
		    struct vlist_node *node_new,
		    struct vlist_node *node_old)
{
	struct network *net = container_of(tree, struct network, peers);
	struct network_peer *h_new = container_of_safe(node_new, struct network_peer, node);
	struct network_peer *h_old = container_of_safe(node_old, struct network_peer, node);
	int ret;

	if (h_new && h_old) {
		memcpy(&h_new->state, &h_old->state, sizeof(h_new->state));

		if (network_peer_equal(h_new, h_old))
			return;
	}

	if (h_new)
		ret = wg_peer_update(net, h_new, h_old ? WG_PEER_UPDATE : WG_PEER_CREATE);
	else
		ret = wg_peer_update(net, h_old, WG_PEER_DELETE);

	if (ret)
		fprintf(stderr, "Failed to %s peer on network %s: %s\n",
			h_new ? "update" : "delete", network_name(net),
			strerror(-ret));
}

static struct network_group *
network_group_get(struct network *net, const char *name)
{
	struct network_group *group;
	char *name_buf;

	group = avl_find_element(&net->groups, name, group, node);
	if (group)
		return group;

	group = calloc_a(sizeof(*group), &name_buf, strlen(name) + 1);
	group->node.key = strcpy(name_buf, name);
	avl_insert(&net->groups, &group->node);

	return group;
}

static void
network_host_add_group(struct network *net, struct network_host *host,
		       const char *name)
{
	struct network_group *group;
	int i;

	group = network_group_get(net, name);
	for (i = 0; i < group->n_members; i++)
		if (group->members[i] == host)
			return;

	group->n_members++;
	group->members = realloc(group->members, group->n_members * sizeof(*group->members));
	group->members[group->n_members - 1] = host;
}

enum {
	NETWORK_HOST_KEY,
	NETWORK_HOST_GROUPS,
	NETWORK_HOST_IPADDR,
	NETWORK_HOST_SUBNET,
	NETWORK_HOST_PORT,
	NETWORK_HOST_PEX_PORT,
	NETWORK_HOST_ENDPOINT,
	NETWORK_HOST_GATEWAY,
	__NETWORK_HOST_MAX
};

static const struct blobmsg_policy host_policy[__NETWORK_HOST_MAX] = {
	[NETWORK_HOST_KEY] = { "key", BLOBMSG_TYPE_STRING },
	[NETWORK_HOST_GROUPS] = { "groups", BLOBMSG_TYPE_ARRAY },
	[NETWORK_HOST_IPADDR] = { "ipaddr", BLOBMSG_TYPE_ARRAY },
	[NETWORK_HOST_SUBNET] = { "subnet", BLOBMSG_TYPE_ARRAY },
	[NETWORK_HOST_PORT] = { "port", BLOBMSG_TYPE_INT32 },
	[NETWORK_HOST_PEX_PORT] = { "peer-exchange-port", BLOBMSG_TYPE_INT32 },
	[NETWORK_HOST_ENDPOINT] = { "endpoint", BLOBMSG_TYPE_STRING },
	[NETWORK_HOST_GATEWAY] = { "gateway", BLOBMSG_TYPE_STRING },
};

static void
network_host_create(struct network *net, struct blob_attr *attr, bool dynamic)
{
	struct blob_attr *tb[__NETWORK_HOST_MAX];
	struct blob_attr *cur, *ipaddr, *subnet;
	uint8_t key[CURVE25519_KEY_SIZE];
	struct network_host *host = NULL;
	struct network_peer *peer;
	int ipaddr_len, subnet_len;
	const char *endpoint, *gateway;
	char *endpoint_buf, *gateway_buf;
	int rem;

	blobmsg_parse(host_policy, __NETWORK_HOST_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));

	if (!tb[NETWORK_HOST_KEY])
		return;

	ipaddr_len = tb[NETWORK_HOST_IPADDR] ? blob_pad_len(tb[NETWORK_HOST_IPADDR]) : 0;
	if (ipaddr_len &&
	    blobmsg_check_array(tb[NETWORK_HOST_IPADDR], BLOBMSG_TYPE_STRING) < 0)
		ipaddr_len = 0;

	subnet_len = tb[NETWORK_HOST_SUBNET] ? blob_pad_len(tb[NETWORK_HOST_SUBNET]) : 0;
	if (subnet_len &&
	    blobmsg_check_array(tb[NETWORK_HOST_SUBNET], BLOBMSG_TYPE_STRING) < 0)
		subnet_len = 0;

	if ((cur = tb[NETWORK_HOST_ENDPOINT]) != NULL)
		endpoint = blobmsg_get_string(cur);
	else
		endpoint = NULL;

	if (!dynamic && (cur = tb[NETWORK_HOST_GATEWAY]) != NULL)
		gateway = blobmsg_get_string(cur);
	else
		gateway = NULL;

	if (b64_decode(blobmsg_get_string(tb[NETWORK_HOST_KEY]), key,
		       sizeof(key)) != sizeof(key))
		return;

	if (dynamic) {
		struct network_dynamic_peer *dyn_peer;

		/* don't override/alter hosts configured via network data */
		peer = vlist_find(&net->peers, key, peer, node);
		if (peer && !peer->dynamic &&
			peer->node.version == net->peers.version)
			return;

		dyn_peer = calloc_a(sizeof(*dyn_peer),
				&ipaddr, ipaddr_len,
				&subnet, subnet_len,
				&endpoint_buf, endpoint ? strlen(endpoint) + 1 : 0);
		list_add_tail(&dyn_peer->list, &net->dynamic_peers);
		peer = &dyn_peer->peer;
	} else {
		const char *name;
		char *name_buf;

		name = blobmsg_name(attr);
		host = avl_find_element(&net->hosts, name, host, node);
		if (host)
			return;

		host = calloc_a(sizeof(*host),
				&name_buf, strlen(name) + 1,
				&ipaddr, ipaddr_len,
				&subnet, subnet_len,
				&endpoint_buf, endpoint ? strlen(endpoint) + 1 : 0,
				&gateway_buf, gateway ? strlen(gateway) + 1 : 0);
		host->node.key = strcpy(name_buf, name);
		peer = &host->peer;
	}

	peer->dynamic = dynamic;
	if ((cur = tb[NETWORK_HOST_IPADDR]) != NULL && ipaddr_len)
		peer->ipaddr = memcpy(ipaddr, cur, ipaddr_len);
	if ((cur = tb[NETWORK_HOST_SUBNET]) != NULL && subnet_len)
		peer->subnet = memcpy(subnet, cur, subnet_len);
	if ((cur = tb[NETWORK_HOST_PORT]) != NULL)
		peer->port = blobmsg_get_u32(cur);
	else
		peer->port = net->net_config.port;
	if ((cur = tb[NETWORK_HOST_PEX_PORT]) != NULL)
		peer->pex_port = blobmsg_get_u32(cur);
	else
		peer->pex_port = net->net_config.pex_port;
	if (endpoint)
		peer->endpoint = strcpy(endpoint_buf, endpoint);
	memcpy(peer->key, key, sizeof(key));

	memcpy(&peer->local_addr.network_id,
		   &net->net_config.addr.network_id,
		   sizeof(peer->local_addr.network_id));
	network_fill_host_addr(&peer->local_addr, peer->key);

	if (!host)
		return;

	if (gateway)
		host->gateway = strcpy(gateway_buf, gateway);

	blobmsg_for_each_attr(cur, tb[NETWORK_HOST_GROUPS], rem) {
		if (!blobmsg_check_attr(cur, false) ||
		    blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		network_host_add_group(net, host, blobmsg_get_string(cur));
	}

	avl_insert(&net->hosts, &host->node);
	if (!memcmp(peer->key, net->config.pubkey, sizeof(key))) {
		if (!net->prev_local_host ||
		    !network_peer_equal(&net->prev_local_host->peer, &host->peer))
			net->net_config.local_host_changed = true;

		net->net_config.local_host = host;
	}
}

static void
network_hosts_load_dynamic_file(struct network *net, const char *file)
{
	struct blob_attr *cur;
	int rem;

	blob_buf_init(&b, 0);

    if (!blobmsg_add_json_from_file(&b, file))
		return;

	blob_for_each_attr(cur, b.head, rem)
		network_host_create(net, cur, true);
}

static void
network_hosts_load_dynamic_peers(struct network *net)
{
	struct network_dynamic_peer *dyn;
	struct blob_attr *cur;
	int rem;

	if (!net->config.peer_data)
		return;

	blobmsg_for_each_attr(cur, net->config.peer_data, rem)
		network_hosts_load_dynamic_file(net, blobmsg_get_string(cur));

	blob_buf_free(&b);

	list_for_each_entry(dyn, &net->dynamic_peers, list)
		vlist_add(&net->peers, &dyn->peer.node, &dyn->peer.key);
}

static void
network_host_free_dynamic_peers(struct list_head *list)
{
	struct network_dynamic_peer *dyn, *dyn_tmp;

	list_for_each_entry_safe(dyn, dyn_tmp, list, list) {
		list_del(&dyn->list);
		free(dyn);
	}
}

void network_hosts_reload_dynamic_peers(struct network *net)
{
	struct network_peer *peer;
	LIST_HEAD(old_entries);

	if (!net->config.peer_data)
		return;

	list_splice_init(&net->dynamic_peers, &old_entries);

	vlist_for_each_element(&net->peers, peer, node)
		if (peer->dynamic)
			peer->node.version = net->peers.version - 1;

	network_hosts_load_dynamic_peers(net);

	vlist_flush(&net->peers);

	network_host_free_dynamic_peers(&old_entries);
}

void network_hosts_update_start(struct network *net)
{
	struct network_host *host, *htmp;
	struct network_group *group, *gtmp;

	avl_remove_all_elements(&net->hosts, host, node, htmp)
		list_add_tail(&host->node.list, &old_hosts);

	avl_remove_all_elements(&net->groups, group, node, gtmp) {
		free(group->members);
		free(group);
	}

	vlist_update(&net->peers);
}

static void
__network_hosts_update_done(struct network *net, bool free_net)
{
	struct network_host *local, *host, *tmp;
	LIST_HEAD(old_dynamic);
	const char *local_name;

	list_splice_init(&net->dynamic_peers, &old_dynamic);
	if (free_net)
		goto out;

	local = net->net_config.local_host;
	if (!local)
		goto out;

	local_name = network_host_name(local);

	if (net->net_config.local_host_changed)
		wg_init_local(net, &local->peer);

	avl_for_each_element(&net->hosts, host, node) {
		if (host == local)
			continue;
		if (host->gateway && strcmp(host->gateway, local_name) != 0)
			continue;
		if (local->gateway && strcmp(local->gateway, network_host_name(host)) != 0)
			continue;
		vlist_add(&net->peers, &host->peer.node, host->peer.key);
	}

	network_hosts_load_dynamic_peers(net);

out:
	vlist_flush(&net->peers);

	network_host_free_dynamic_peers(&old_dynamic);

	list_for_each_entry_safe(host, tmp, &old_hosts, node.list) {
		list_del(&host->node.list);
		free(host);
	}
}

void network_hosts_update_done(struct network *net)
{
	return __network_hosts_update_done(net, false);
}

static union network_endpoint *
network_peer_next_endpoint(struct network_peer *peer)
{
	union network_endpoint *ep;
	int i;

	for (i = 0; i < __ENDPOINT_TYPE_MAX; i++) {
		int cur = peer->state.next_endpoint_idx;

		if (++peer->state.next_endpoint_idx == __ENDPOINT_TYPE_MAX)
			peer->state.next_endpoint_idx = 0;

		ep = &peer->state.next_endpoint[cur];
		if (cur == ENDPOINT_TYPE_STATIC &&
			(!peer->endpoint ||
		     network_get_endpoint(ep, AF_UNSPEC, peer->endpoint, peer->port,
					  peer->state.connect_attempt++)))
			continue;

		if (!ep->sa.sa_family)
			continue;

		return ep;
	}

	return NULL;
}


static void
network_hosts_connect_cb(struct uloop_timeout *t)
{
	struct network *net = container_of(t, struct network, connect_timer);
	struct network_host *host;
	struct network_peer *peer;
	union network_endpoint *ep;

	avl_for_each_element(&net->hosts, host, node)
		host->peer.state.num_net_queries = 0;
	net->num_net_queries = 0;

	if (!net->net_config.keepalive || !net->net_config.local_host)
		return;

	wg_peer_refresh(net);

	vlist_for_each_element(&net->peers, peer, node) {
		if (peer->state.connected)
			continue;

		ep = network_peer_next_endpoint(peer);
		if (!ep)
			continue;

		if (memcmp(ep, &peer->state.endpoint, sizeof(*ep)) != 0 &&
		    !network_skip_endpoint_route(net, ep))
			unetd_ubus_netifd_add_route(net, ep);

		wg_peer_connect(net, peer, ep);
	}

	network_pex_event(net, NULL, PEX_EV_QUERY);

	uloop_timeout_set(t, 1000);
}

void network_hosts_add(struct network *net, struct blob_attr *hosts)
{
	struct blob_attr *cur;
	int rem;

	blobmsg_for_each_attr(cur, hosts, rem)
		network_host_create(net, cur, false);
}

void network_hosts_init(struct network *net)
{
	INIT_LIST_HEAD(&net->dynamic_peers);
	avl_init(&net->hosts, avl_strcmp, false, NULL);
	vlist_init(&net->peers, avl_key_cmp, network_peer_update);
	avl_init(&net->groups, avl_strcmp, false, NULL);
	net->connect_timer.cb = network_hosts_connect_cb;
}

void network_hosts_free(struct network *net)
{
	uloop_timeout_cancel(&net->connect_timer);
	network_hosts_update_start(net);
	__network_hosts_update_done(net, true);
}
