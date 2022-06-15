// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include "unetd.h"

struct vxlan_tunnel {
	struct network *net;
	struct network_service *s;
	char ifname[IFNAMSIZ + 1];
	int ifindex;
	uint16_t mtu;
	uint16_t port;
	uint32_t vni;
	uint32_t *forward_ports;
	uint32_t *cur_forward_ports;
	bool active;
};

static struct nl_sock *rtnl;
static bool ignore_errors;

static int
unetd_nl_error_cb(struct sockaddr_nl *nla, struct nlmsgerr *err,
		   void *arg)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *) err - 1;
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1];
	struct nlattr *attrs;
	int ack_len = sizeof(*nlh) + sizeof(int) + sizeof(*nlh);
	int len = nlh->nlmsg_len;
	const char *errstr = "(unknown)";

	if (ignore_errors)
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return NL_STOP;

	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		ack_len += err->msg.nlmsg_len - sizeof(*nlh);

	attrs = (void *) ((unsigned char *) nlh + ack_len);
	len -= ack_len;

	nla_parse(tb, NLMSGERR_ATTR_MAX, attrs, len, NULL);
	if (tb[NLMSGERR_ATTR_MSG])
		errstr = nla_data(tb[NLMSGERR_ATTR_MSG]);

	D("Netlink error(%d): %s\n", err->error, errstr);

	return NL_STOP;
}

static struct nl_msg *vxlan_rtnl_msg(const char *ifname, int type, int flags)
{
	struct ifinfomsg iim = {
		.ifi_family = AF_UNSPEC,
	};
	struct nl_msg *msg;

	msg = nlmsg_alloc_simple(type, flags | NLM_F_REQUEST);
	if (!msg)
		return NULL;

	nlmsg_append(msg, &iim, sizeof(iim), 0);
	nla_put_string(msg, IFLA_IFNAME, ifname);

	return msg;
}

static int vxlan_rtnl_call(struct nl_msg *msg)
{
	int ret;

	ret = nl_send_auto_complete(rtnl, msg);
	nlmsg_free(msg);

	if (ret < 0)
		return ret;

	return nl_wait_for_ack(rtnl);
}

static int
vxlan_rtnl_init(void)
{
	int fd, opt;

	if (rtnl)
		return 0;

	rtnl = nl_socket_alloc();
	if (!rtnl)
		return -1;

	if (nl_connect(rtnl, NETLINK_ROUTE))
		goto free;

	nl_socket_disable_seq_check(rtnl);
	nl_socket_set_buffer_size(rtnl, 65536, 0);
	nl_cb_err(nl_socket_get_cb(rtnl), NL_CB_CUSTOM, unetd_nl_error_cb, NULL);

	fd = nl_socket_get_fd(rtnl);

	opt = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &opt, sizeof(opt));

	opt = 1;
	setsockopt(fd, SOL_NETLINK, NETLINK_CAP_ACK, &opt, sizeof(opt));

	return 0;

free:
	nl_socket_free(rtnl);
	rtnl = NULL;
	return -1;
}

static uint32_t
vxlan_tunnel_id(struct vxlan_tunnel *vt)
{
	siphash_key_t key = {};
	const char *name = network_service_name(vt->s);
	uint64_t val;

	if (vt->vni != ~0)
		return vt->vni;

	siphash_to_le64(&val, name, strlen(name), &key);

	return val & 0x00ffffff;
}

static int
vxlan_update_host_fdb_entry(struct vxlan_tunnel *vt, struct network_host *host, bool add)
{
	struct ndmsg ndmsg = {
		.ndm_family = PF_BRIDGE,
		.ndm_state = NUD_NOARP | NUD_PERMANENT,
		.ndm_flags = NTF_SELF,
		.ndm_ifindex = vt->ifindex,
	};
	unsigned int flags = NLM_F_REQUEST;
	uint8_t lladdr[ETH_ALEN] = {};
	struct nl_msg *msg;

	if (add)
		flags |= NLM_F_CREATE | NLM_F_APPEND;

	msg = nlmsg_alloc_simple(add ? RTM_NEWNEIGH : RTM_DELNEIGH, flags);
	nlmsg_append(msg, &ndmsg, sizeof(ndmsg), 0);
	nla_put(msg, NDA_LLADDR, ETH_ALEN, lladdr);
	nla_put(msg, NDA_DST, sizeof(struct in6_addr), &host->peer.local_addr);
	nla_put_u32(msg, NDA_IFINDEX, vt->net->ifindex);

	return vxlan_rtnl_call(msg);
}

static void
vxlan_update_fdb_hosts(struct vxlan_tunnel *vt)
{
	struct network_service *s = vt->s;
	bool active;
	int i;

	if (!vt->active)
		return;

	for (i = 0; i < s->n_members; i++) {
		if (s->members[i] == vt->net->net_config.local_host)
			continue;

		if (vt->forward_ports && !bitmask_test(vt->forward_ports, i))
			continue;

		active = s->members[i]->peer.state.connected;
		if (active == bitmask_test(vt->cur_forward_ports, i))
			continue;

		if (!vxlan_update_host_fdb_entry(vt, s->members[i], active))
			bitmask_set_val(vt->cur_forward_ports, i, active);
	}
}

static void
vxlan_peer_update(struct network *net, struct network_service *s, struct network_peer *peer)
{
	if (!s->vxlan)
		return;

	vxlan_update_fdb_hosts(s->vxlan);
}

static void
vxlan_tunnel_init(struct vxlan_tunnel *vt)
{
	struct network_peer *local = &vt->net->net_config.local_host->peer;
	struct nlattr *linkinfo, *data;
	struct nl_msg *msg;

	if (vxlan_rtnl_init())
		return;

	msg = vxlan_rtnl_msg(vt->ifname, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL);

	linkinfo = nla_nest_start(msg, IFLA_LINKINFO);
	nla_put_string(msg, IFLA_INFO_KIND, "vxlan");
	nla_put_u32(msg, IFLA_MTU, vt->mtu);

	data = nla_nest_start(msg, IFLA_INFO_DATA);
	nla_put_u32(msg, IFLA_VXLAN_ID, vxlan_tunnel_id(vt));
	nla_put(msg, IFLA_VXLAN_LOCAL6, sizeof(struct in6_addr), &local->local_addr);
	nla_put_u16(msg, IFLA_VXLAN_PORT, vt->port);
	nla_put_u8(msg, IFLA_VXLAN_LEARNING, 1);
	nla_nest_end(msg, data);

	nla_nest_end(msg, linkinfo);

	if (vxlan_rtnl_call(msg) < 0)
		return;

	vt->ifindex = if_nametoindex(vt->ifname);
	if (!vt->ifindex) {
		D_SERVICE(vt->net, vt->s, "failed to get ifindex for device %s", vt->ifname);
		return;
	}

	vt->active = true;
	vxlan_update_fdb_hosts(vt);
}

static void
vxlan_tunnel_teardown(struct vxlan_tunnel *vt)
{
	struct nl_msg *msg;

	if (!rtnl)
		return;

	vt->active = false;
	msg = vxlan_rtnl_msg(vt->ifname, RTM_DELLINK, 0);
	vxlan_rtnl_call(msg);
}

static const char *
vxlan_find_ifname(struct network *net, const char *service)
{
	struct blob_attr *cur;
	int rem;

	if (!net->config.tunnels)
		return NULL;

	blobmsg_for_each_attr(cur, net->config.tunnels, rem) {
		const char *name;

		if (!blobmsg_check_attr(cur, true) ||
		    blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		if (strcmp(blobmsg_get_string(cur), service) != 0)
			continue;

		name = blobmsg_name(cur);
		if (strlen(name) > IFNAMSIZ)
			break;

		return name;
	}

	return NULL;
}

static void
__vxlan_mark_forward_host(struct vxlan_tunnel *vt, struct network_host *host)
{
	struct network_service *s = vt->s;
	unsigned int i;

	for (i = 0; i < s->n_members; i++) {
		if (s->members[i] != host)
			continue;

		bitmask_set(vt->forward_ports, i);
		break;
	}
}

static void
vxlan_mark_forward_host(struct vxlan_tunnel *vt, const char *name)
{
	struct network *net = vt->net;
	struct network_host *host;

	host = avl_find_element(&net->hosts, name, host, node);
	if (!host)
		return;

	__vxlan_mark_forward_host(vt, host);
}

static void
vxlan_mark_forward_group(struct vxlan_tunnel *vt, const char *name)
{
	struct network *net = vt->net;
	struct network_group *group;
	int i;

	group = avl_find_element(&net->groups, name, group, node);
	if (!group)
		return;

	for (i = 0; i < group->n_members; i++)
		__vxlan_mark_forward_host(vt, group->members[i]);
}

static void
vxlan_init_forward_ports(struct vxlan_tunnel *vt, struct blob_attr *data)
{
	unsigned int len = bitmask_size(vt->s->n_members);
	struct blob_attr *cur;
	int rem;

	vt->cur_forward_ports = realloc(vt->cur_forward_ports, len);
	memset(vt->cur_forward_ports, 0, len);

	if (!data || blobmsg_check_array(data, BLOBMSG_TYPE_STRING) <= 0) {
		free(vt->forward_ports);
		vt->forward_ports = NULL;
		return;
	}

	vt->forward_ports = realloc(vt->forward_ports, len);
	memset(vt->forward_ports, 0, len);
	blobmsg_for_each_attr(cur, data, rem) {
		const char *name = blobmsg_get_string(cur);

		if (name[0] == '@')
			vxlan_mark_forward_group(vt, name + 1);
		else
			vxlan_mark_forward_host(vt, name);
	}
}

static bool
vxlan_config_equal(struct network_service *s1, struct network_service *s2)
{
	int i;

	if (!blob_attr_equal(s1->config, s2->config))
		return false;

	if (s1->n_members != s2->n_members)
		return false;

	for (i = 0; i < s1->n_members; i++)
		if (memcmp(s1->members[i]->peer.key, s2->members[i]->peer.key,
			   CURVE25519_KEY_SIZE) != 0)
			return false;

	return true;
}

static void
vxlan_init(struct network *net, struct network_service *s,
	   struct network_service *s_old)
{
	enum {
		VXCFG_ATTR_FWD_PORTS,
		VXCFG_ATTR_ID,
		VXCFG_ATTR_PORT,
		VXCFG_ATTR_MTU,
		__VXCFG_ATTR_MAX
	};
	static const struct blobmsg_policy policy[__VXCFG_ATTR_MAX] = {
		[VXCFG_ATTR_FWD_PORTS] = { "forward_ports", BLOBMSG_TYPE_ARRAY },
		[VXCFG_ATTR_ID] = { "id", BLOBMSG_TYPE_INT32 },
		[VXCFG_ATTR_PORT] = { "port", BLOBMSG_TYPE_INT32 },
		[VXCFG_ATTR_MTU] = { "mtu", BLOBMSG_TYPE_INT32 },
	};
	struct blob_attr *tb[__VXCFG_ATTR_MAX] = {};
	struct blob_attr *cur;
	struct vxlan_tunnel *vt = s->vxlan;
	const char *name;

	if (s_old) {
		vt = s_old->vxlan;
		s_old->vxlan = NULL;
		if (!vt)
			return;

		if (vxlan_config_equal(s, s_old)) {
			s->vxlan = vt;
			vt->s = s;
			return;
		}

		vxlan_tunnel_teardown(vt);
		goto init;
	}

	name = vxlan_find_ifname(net, network_service_name(s));
	if (!name) {
		D_SERVICE(net, s, "no configured tunnel ifname");
		return;
	}

	vt = calloc(1, sizeof(*s->vxlan));
	snprintf(vt->ifname, sizeof(vt->ifname), "%s", name);
	vt->net = net;

init:
	s->vxlan = vt;
	vt->s = s;
	if (s->config)
		blobmsg_parse(policy, __VXCFG_ATTR_MAX, tb, blobmsg_data(s->config),
			      blobmsg_len(s->config));

	vxlan_init_forward_ports(vt, tb[VXCFG_ATTR_FWD_PORTS]);
	if ((cur = tb[VXCFG_ATTR_ID]) != NULL)
		vt->vni = blobmsg_get_u32(cur) & 0x00ffffff;
	else
		vt->vni = ~0;

	if ((cur = tb[VXCFG_ATTR_PORT]) != NULL)
		vt->port = blobmsg_get_u32(cur);
	else
		vt->port = 4789;

	if ((cur = tb[VXCFG_ATTR_MTU]) != NULL)
		vt->mtu = blobmsg_get_u32(cur);
	else
		vt->mtu = 1500;

	vxlan_tunnel_init(vt);
}

static void
vxlan_free(struct network *net, struct network_service *s)
{
	struct vxlan_tunnel *vt = s->vxlan;

	if (!vt)
		return;

	vxlan_tunnel_teardown(vt);
	s->vxlan = NULL;
	free(vt->forward_ports);
	free(vt);
}

const struct service_ops vxlan_ops = {
	.init = vxlan_init,
	.free = vxlan_free,
	.peer_update = vxlan_peer_update,
};
