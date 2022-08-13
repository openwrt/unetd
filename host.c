// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <libubox/avl-cmp.h>
#include "unetd.h"

static LIST_HEAD(old_hosts);

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

static void
network_host_create(struct network *net, struct blob_attr *attr)
{
	enum {
		NETWORK_HOST_KEY,
		NETWORK_HOST_GROUPS,
		NETWORK_HOST_IPADDR,
		NETWORK_HOST_SUBNET,
		NETWORK_HOST_PORT,
		NETWORK_HOST_ENDPOINT,
		__NETWORK_HOST_MAX
	};
	static const struct blobmsg_policy policy[__NETWORK_HOST_MAX] = {
		[NETWORK_HOST_KEY] = { "key", BLOBMSG_TYPE_STRING },
		[NETWORK_HOST_GROUPS] = { "groups", BLOBMSG_TYPE_ARRAY },
		[NETWORK_HOST_IPADDR] = { "ipaddr", BLOBMSG_TYPE_ARRAY },
		[NETWORK_HOST_SUBNET] = { "subnet", BLOBMSG_TYPE_ARRAY },
		[NETWORK_HOST_PORT] = { "port", BLOBMSG_TYPE_INT32 },
		[NETWORK_HOST_ENDPOINT] = { "endpoint", BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[__NETWORK_HOST_MAX];
	struct blob_attr *cur, *ipaddr, *subnet;
	uint8_t key[CURVE25519_KEY_SIZE];
	struct network_host *host;
	struct network_peer *peer;
	int ipaddr_len, subnet_len;
	const char *name, *endpoint;
	char *name_buf, *endpoint_buf;
	int rem;

	blobmsg_parse(policy, __NETWORK_HOST_MAX, tb, blobmsg_data(attr), blobmsg_len(attr));

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

	if (b64_decode(blobmsg_get_string(tb[NETWORK_HOST_KEY]), key,
		       sizeof(key)) != sizeof(key))
		return;

	name = blobmsg_name(attr);
	host = avl_find_element(&net->hosts, name, host, node);
	if (host)
		return;

	host = calloc_a(sizeof(*host),
			&name_buf, strlen(name) + 1,
			&ipaddr, ipaddr_len,
			&subnet, subnet_len,
			&endpoint_buf, endpoint ? strlen(endpoint) + 1 : 0);
	peer = &host->peer;
	if ((cur = tb[NETWORK_HOST_IPADDR]) != NULL && ipaddr_len)
		peer->ipaddr = memcpy(ipaddr, cur, ipaddr_len);
	if ((cur = tb[NETWORK_HOST_SUBNET]) != NULL && subnet_len)
		peer->subnet = memcpy(subnet, cur, subnet_len);
	if ((cur = tb[NETWORK_HOST_PORT]) != NULL)
		peer->port = blobmsg_get_u32(cur);
	else
		peer->port = net->net_config.port;
	if (endpoint)
		peer->endpoint = strcpy(endpoint_buf, endpoint);
	memcpy(peer->key, key, sizeof(key));
	host->node.key = strcpy(name_buf, name);

	memcpy(&peer->local_addr.network_id,
		   &net->net_config.addr.network_id,
		   sizeof(peer->local_addr.network_id));
	network_fill_host_addr(&peer->local_addr, peer->key);

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

void network_hosts_update_done(struct network *net)
{
	struct network_host *host, *tmp;

	if (!net->net_config.local_host)
		goto out;

	if (net->net_config.local_host_changed)
		wg_init_local(net, &net->net_config.local_host->peer);

	avl_for_each_element(&net->hosts, host, node)
		if (host != net->net_config.local_host)
			vlist_add(&net->peers, &host->peer.node, host->peer.key);

out:
	vlist_flush(&net->peers);

	list_for_each_entry_safe(host, tmp, &old_hosts, node.list) {
		list_del(&host->node.list);
		free(host);
	}
}

static void
network_hosts_connect_cb(struct uloop_timeout *t)
{
	struct network *net = container_of(t, struct network, connect_timer);
	struct network_host *host;
	union network_endpoint *ep;

	avl_for_each_element(&net->hosts, host, node)
		host->peer.state.num_net_queries = 0;
	net->num_net_queries = 0;

	if (!net->net_config.keepalive)
		return;

	wg_peer_refresh(net);

	avl_for_each_element(&net->hosts, host, node) {
		struct network_peer *peer = &host->peer;

		if (host == net->net_config.local_host)
			continue;

		if (peer->state.connected)
			continue;

		ep = &peer->state.next_endpoint;
		if (peer->endpoint &&
		    network_get_endpoint(ep, peer->endpoint, peer->port,
					 peer->state.connect_attempt++))
			continue;

		if (!ep->sa.sa_family)
			continue;

		if (memcmp(ep, &peer->state.endpoint, sizeof(*ep)) != 0)
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
		network_host_create(net, cur);
}

void network_hosts_init(struct network *net)
{
	avl_init(&net->hosts, avl_strcmp, false, NULL);
	vlist_init(&net->peers, avl_key_cmp, network_peer_update);
	avl_init(&net->groups, avl_strcmp, false, NULL);
	net->connect_timer.cb = network_hosts_connect_cb;
}

void network_hosts_free(struct network *net)
{
	uloop_timeout_cancel(&net->connect_timer);
	network_hosts_update_start(net);
	network_hosts_update_done(net);
}
