// SPDX-License-Identifier: GPL-2.0-or-later
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
int global_pex_port = UNETD_GLOBAL_PEX_PORT;

static bool debug;

#ifdef UBUS_SUPPORT
static struct udebug ud;
static struct udebug_buf udb_log;

static const struct udebug_buf_meta meta_log = {
	.name = "log",
	.format = UDEBUG_FORMAT_STRING
};

static struct udebug_ubus_ring rings[] = {
	{
		.buf = &udb_log,
		.meta = &meta_log,
		.default_entries = 1024,
		.default_size = 64 * 1024,
	}
};
#endif

bool unetd_debug_active(void)
{
#ifdef UBUS_SUPPORT
	if (udebug_buf_valid(&udb_log))
		return true;
#endif
	return debug;
}

static void __attribute__((format (printf, 1, 0)))
unetd_udebug_vprintf(const char *format, va_list ap)
{
#ifdef UBUS_SUPPORT
	if (!udebug_buf_valid(&udb_log))
		return;

	udebug_entry_init(&udb_log);
	udebug_entry_vprintf(&udb_log, format, ap);
	udebug_entry_add(&udb_log);
#endif
}

void unetd_debug_printf(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	if (debug) {
		va_list ap2;

		va_copy(ap2, ap);
		vfprintf(stderr, format, ap2);
		va_end(ap2);
	}

	unetd_udebug_vprintf(format, ap);
	va_end(ap);
}

#ifdef UBUS_SUPPORT
void unetd_udebug_config(struct udebug_ubus *ctx, struct blob_attr *data,
			 bool enabled)
{
	udebug_ubus_apply_config(&ud, rings, ARRAY_SIZE(rings), data, enabled);
}
#endif

static void
network_write_hosts(struct network *net, FILE *f)
{
	struct network_host *host;
	char ip[INET6_ADDRSTRLEN];

	if (!net->net_config.local_host)
		return;

	avl_for_each_element(&net->hosts, host, node) {
		inet_ntop(AF_INET6, &host->peer.local_addr, ip, sizeof(ip));
		fprintf(f, "%s\t%s%s%s\n", ip, network_host_name(host),
			net->config.domain ? "." : "",
			net->config.domain ? net->config.domain : "");
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

	if (asprintf(&tmpfile, "%s.XXXXXXXX", hosts_file) < 0)
		return;

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
	const char *unix_socket = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "D:dh:u:M:N:P:")) != -1) {
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
		case 'P':
			global_pex_port = atoi(optarg);
			break;
		case 'u':
			unix_socket = optarg;
			break;
		}
	}

	uloop_init();
#ifdef UBUS_SUPPORT
	udebug_init(&ud);
	udebug_auto_connect(&ud, NULL);
	for (size_t i = 0; i < ARRAY_SIZE(rings); i++)
		udebug_ubus_ring_init(&ud, &rings[i]);
#endif

	unetd_ubus_init();
	unetd_write_hosts();
	global_pex_open(unix_socket);
	add_networks();
	uloop_run();
	pex_close();
	network_free_all();
	uloop_done();

	return 0;
}
