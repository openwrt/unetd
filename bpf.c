// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <netinet/if_ether.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/socket.h>
#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "unetd.h"

static int unetd_bpf_pr(enum libbpf_print_level level, const char *format,
		     va_list args)
{
	return vfprintf(stderr, format, args);
}

static void unetd_init_env(void)
{
	struct rlimit limit = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	setrlimit(RLIMIT_MEMLOCK, &limit);
}

static void
unetd_set_prog_mtu(struct bpf_object *obj, uint32_t mtu)
{
	struct bpf_map *map = NULL;

	while ((map = bpf_object__next_map(obj, map)) != NULL) {
		if (!strstr(bpf_map__name(map), ".rodata"))
			continue;

		bpf_map__set_initial_value(map, &mtu, sizeof(mtu));
	}
}

static int
unetd_attach_bpf_prog(int ifindex, int fd, bool egress)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
			    .attach_point = egress ? BPF_TC_EGRESS : BPF_TC_INGRESS,
			    .ifindex = ifindex);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, attach_tc,
			    .flags = BPF_TC_F_REPLACE,
			    .handle = 1,
				.prog_fd = fd,
			    .priority = UNETD_MSS_PRIO_BASE);

	bpf_tc_hook_create(&hook);

	return bpf_tc_attach(&hook, &attach_tc);
}

int unetd_attach_mssfix(int ifindex, int mtu)
{
	struct bpf_program *prog;
	struct bpf_object *obj;
	int prog_fd;
	int ret = -1;

	if (rtnl_init())
		return -1;

	unetd_init_env();
	libbpf_set_print(unetd_bpf_pr);

	obj = bpf_object__open_file(mssfix_path, NULL);
	if (libbpf_get_error(obj)) {
		perror("bpf_object__open_file");
		goto out;
	}

	prog = bpf_object__find_program_by_name(obj, "mssfix");
	if (!prog) {
		perror("bpf_object__find_program_by_name");
		goto out;
	}

	bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

	unetd_set_prog_mtu(obj, mtu);

	if (bpf_object__load(obj)) {
		perror("bpf_object__load");
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	unetd_attach_bpf_prog(ifindex, prog_fd, true);
	unetd_attach_bpf_prog(ifindex, prog_fd, false);

	ret = 0;

out:
	bpf_object__close(obj);

	return ret;
}
