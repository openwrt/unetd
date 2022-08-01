// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <unistd.h>
#include <arpa/inet.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include "unetd.h"

struct cmdline_network {
	struct cmdline_network *next;
	char *data;
};

static struct cmdline_network *cmd_nets;
static const char *hosts_file;
const char *mssfix_path = UNETD_MSS_BPF_PATH;
const char *data_dir = UNETD_DATA_DIR;
bool debug;

static void
network_write_hosts(struct network *net, FILE *f)
{
	struct network_host *host;
	char ip[INET6_ADDRSTRLEN];

	if (!net->net_config.local_host)
		return;

	avl_for_each_element(&net->hosts, host, node) {
		inet_ntop(AF_INET6, &host->peer.local_addr, ip, sizeof(ip));
		fprintf(f, "%s\t%s\n", ip, network_host_name(host));
	}
}

void unetd_write_hosts(void)
{
	struct network *net;
	char *tmpfile = NULL;
	FILE *f;
	int fd;

	if (!hosts_file)
		return;

	asprintf(&tmpfile, "%s.XXXXXXXX", hosts_file);
	fd = mkstemp(tmpfile);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

	chmod(tmpfile, 0644);
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		goto out;
	}

	avl_for_each_element(&networks, net, node)
		network_write_hosts(net, f);

	fclose(f);

	if (rename(tmpfile, hosts_file))
		unlink(tmpfile);

out:
	free(tmpfile);
}

static void add_networks(void)
{
	struct cmdline_network *net;
	static struct blob_buf b;
	struct blob_attr *name;

	for (net = cmd_nets; net; net = net->next) {
		blob_buf_init(&b, 0);
		if (!blobmsg_add_json_from_string(&b, net->data))
			continue;

		blobmsg_parse(&network_policy[NETWORK_ATTR_NAME], 1, &name,
			      blobmsg_data(b.head), blobmsg_len(b.head));
		if (!name)
			continue;

		unetd_network_add(blobmsg_get_string(name), b.head);
	}

	blob_buf_free(&b);
}

int main(int argc, char **argv)
{
	struct cmdline_network *net;
	int ch;

	while ((ch = getopt(argc, argv, "D:dh:M:N:")) != -1) {
		switch (ch) {
		case 'D':
			data_dir = optarg;
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			hosts_file = optarg;
			break;
		case 'N':
			net = calloc(1, sizeof(*net));
			net->next = cmd_nets;
			net->data = optarg;
			cmd_nets = net;
			break;
		case 'M':
			mssfix_path = optarg;
			break;
		}
	}

	uloop_init();
	unetd_ubus_init();
	unetd_write_hosts();
	add_networks();
	uloop_run();
	network_free_all();
	uloop_done();

	return 0;
}
