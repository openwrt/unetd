#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/blob.h>

#include "curve25519.h"
#include "siphash.h"
#include "sha512.h"
#include "dht.h"
#include "udht.h"
#include "pex-msg.h"

static struct uloop_timeout periodic_timer, peer_timer, status_timer, disconnect_timer;
static struct uloop_fd dht_fd;
static int dht_unix_fd;
static LIST_HEAD(bootstrap_peers);
static LIST_HEAD(networks);
static struct blob_buf b;
static uint8_t local_id[20];
static const char *node_file;
static const char *unix_path;
static bool udht_connected;

static struct {
	unsigned int tick;
	unsigned int peer_count;
	bool bootstrap_added;
	bool dht_ready;
} state;

struct network_entry {
	struct list_head list;
	uint8_t auth_key[CURVE25519_KEY_SIZE];
	uint8_t id[20];
	struct uloop_timeout search_timer;
	int search_count;
	int seq;
};

struct peer_entry {
	struct list_head list;

	struct sockaddr_storage sa;
	int sa_len;
};

void dht_hash(void *hash_return, int hash_size,
	      const void *v1, int len1,
	      const void *v2, int len2,
	      const void *v3, int len3)
{
	siphash_key_t key = {};

	if (hash_size != 8)
	    abort();

	key.key[0] = siphash(v1, len1, &key);
	key.key[1] = siphash(v2, len2, &key);
	siphash_to_le64(hash_return, v3, len3, &key);
}

int dht_sendto(int sockfd, const void *buf, int len, int flags,
	       const struct sockaddr *to, int tolen)
{
	struct iovec iov[2] = {
		{ .iov_base = (void *)to },
		{ .iov_base = (void *)buf, .iov_len = len },
	};
	struct msghdr msg = {
		.msg_iov = iov,
		.msg_iovlen = ARRAY_SIZE(iov),
	};
	int ret;

	if (to->sa_family == AF_INET)
		iov[0].iov_len = sizeof(struct sockaddr_in);
	else if (to->sa_family == AF_INET6)
		iov[0].iov_len = sizeof(struct sockaddr_in6);
	else
		return -1;

	ret = sendmsg(sockfd, &msg, flags);
	if (ret < 0) {
		perror("send");
		if (errno == ECONNRESET || errno == EDESTADDRREQ ||
		    errno == ENOTCONN || errno == ECONNREFUSED)
			uloop_timeout_set(&disconnect_timer, 1);
	}
	return ret;
}

int dht_blacklisted(const struct sockaddr *sa, int salen)
{
	return 0;
}

int dht_random_bytes(void *buf, size_t size)
{
	int fd, rc, save;

	fd = open("/dev/urandom", O_RDONLY);
	if(fd < 0)
		return -1;

	rc = read(fd, buf, size);

	save = errno;
	close(fd);
	errno = save;

	return rc;
}

static void
udht_start_search(void)
{
	struct network_entry *n;

	if (!state.dht_ready)
		return;

	list_for_each_entry(n, &networks, list) {
		if (n->search_timer.pending)
			continue;

		uloop_timeout_set(&n->search_timer, 1);
	}
}

static void
udht_send_v4_node(const void *id, const void *data)
{
	struct network_entry *n;

	struct {
		struct sockaddr sa;
		struct pex_msg_local_control local;
	} msg = {
		.sa = {
			.sa_family = AF_LOCAL
		},
		.local = {
			.ep.in = {
				.sin_family = AF_INET,
				.sin_addr = *(const struct in_addr *)data,
				.sin_port = *(const uint16_t *)(data + 4),
			},
			.timeout = 15 * 60,
		}
	};

	list_for_each_entry(n, &networks, list) {
		if (memcmp(n->id, id, sizeof(n->id)) != 0)
			continue;

		memcpy(&msg.local.auth_id, n->auth_key, sizeof(msg.local.auth_id));
		goto found;
	}

found:
	send(dht_unix_fd, &msg, sizeof(msg), 0);
}

static void
udht_cb(void *closure, int event, const unsigned char *info_hash,
	const void *data, size_t data_len)
{
	char addrbuf[INET6_ADDRSTRLEN];
	int i;

	if (!udht_connected)
		return;

	if (event == DHT_EVENT_SEARCH_DONE) {
		printf("Search done.\n");
		udht_start_search();
	} else if (event == DHT_EVENT_SEARCH_DONE6) {
		printf("IPv6 search done.\n");
	} else if (event == DHT_EVENT_VALUES) {
		printf("Received %d values.\n", (int)(data_len / 6));
		for (i = 0; i < data_len / 6; i++) {
			fprintf(stderr, "Node: %s:%d\n", inet_ntop(AF_INET, data, addrbuf, sizeof(addrbuf)), ntohs(*(uint16_t *)(data + 4)));
			udht_send_v4_node(info_hash, data);
			data += 6;
		}
	}
	else if (event == DHT_EVENT_VALUES6)
		printf("Received %d IPv6 values.\n", (int)(data_len / 18));
	else
		printf("Unknown DHT event %d.\n", event);
}

static void
udht_search_timer_cb(struct uloop_timeout *t)
{
	struct network_entry *n = container_of(t, struct network_entry, search_timer);
	char id_str[42];
	int i;

	for (i = 0; i < sizeof(n->id); i++)
		snprintf(&id_str[i * 2], sizeof(id_str) - i * 2, "%02x", n->id[i]);

	fprintf(stderr, "Start search for network, id=%s\n", id_str);
	dht_search(n->id, UNETD_GLOBAL_PEX_PORT, AF_INET, udht_cb, NULL);

	if (++n->search_count > 2)
		uloop_timeout_set(&n->search_timer, 30 * 1000);
}

static void
udht_timer_cb(struct uloop_timeout *t)
{
	time_t tosleep = 1;

	dht_periodic(NULL, 0, NULL, 0, &tosleep, udht_cb, NULL);
	if (!tosleep)
		tosleep = 1;
	uloop_timeout_set(t, tosleep * 1000);
}

static void
udht_fd_cb(struct uloop_fd *fd, unsigned int events)
{
	static char buf[4096];
	struct sockaddr *sa = (struct sockaddr *)buf;
	time_t tosleep = 1;
	int len;

	while (1) {
		socklen_t fromlen;

		len = recv(fd->fd, buf, sizeof(buf) - 1, 0);
		if (len < 0) {
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN)
				break;

			perror("recvfrom");
			uloop_timeout_set(&disconnect_timer, 1);
			return;
		}

		if (len <= sizeof(struct sockaddr))
			continue;

		if (sa->sa_family == AF_INET)
			fromlen = sizeof(struct sockaddr_in);
		else if (sa->sa_family == AF_INET6)
			fromlen = sizeof(struct sockaddr_in6);
		else
			continue;

		if (len <= fromlen)
			continue;

		buf[len] = 0;
		dht_periodic(buf + fromlen, len - fromlen, sa, fromlen,
			     &tosleep, udht_cb, NULL);
		if (!tosleep)
			tosleep = 1;
		uloop_timeout_set(&periodic_timer, tosleep * 1000);
	}
}

static int
udht_open_socket(const char *unix_path)
{
	uint8_t fd_buf[CMSG_SPACE(sizeof(int))] = { 0 };
	static struct sockaddr sa = {
		.sa_family = AF_LOCAL,
	};
	static struct iovec iov = {
		.iov_base = &sa,
		.iov_len = sizeof(sa),
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = fd_buf,
		.msg_controllen = CMSG_LEN(sizeof(int)),
	};
	struct cmsghdr *cmsg;
	int sfd[2];
	int fd;

	fd = usock(USOCK_UNIX | USOCK_UDP, unix_path, NULL);
	if (fd < 0)
		return -1;

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sfd) < 0)
		close(fd);

	dht_unix_fd = fd;
	dht_fd.fd = sfd[1];
	dht_fd.cb = udht_fd_cb;
	uloop_fd_add(&dht_fd, ULOOP_READ);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	*(int *)CMSG_DATA(cmsg) = sfd[0];

	sendmsg(dht_unix_fd, &msg, 0);
	close(sfd[0]);

	return 0;
}

static void
udht_close_socket(void)
{
	uloop_fd_delete(&dht_fd);
	close(dht_fd.fd);
	close(dht_unix_fd);
}

static void udht_id_hash(uint8_t *dest, const void *data, int len)
{
	struct sha512_state s;
	uint8_t hash[SHA512_HASH_SIZE];

	sha512_init(&s);
	sha512_add(&s, data, len);
	sha512_final(&s, hash);
	memcpy(dest, hash, 20);
}

static void udht_add_peer(const void *data, int len)
{
	const struct sockaddr *sa = data;
	struct peer_entry *p;

	p = calloc(1, sizeof(*p));
	memcpy(&p->sa, sa, len);
	p->sa_len = len;
	list_add_tail(&p->list, &bootstrap_peers);

	if (!peer_timer.pending)
		uloop_timeout_set(&peer_timer, 1);
}

static void udht_add_bootstrap_peer(void)
{
	const struct addrinfo hints = {
		.ai_family = AF_INET,
		.ai_socktype = SOCK_DGRAM,
		.ai_flags = AI_ADDRCONFIG,
	};
	struct addrinfo *res, *cur;
	static const char * const bootstrap_hosts[] = {
		"router.bittorrent.com",
		"router.utorrent.com",
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(bootstrap_hosts); i++) {
		if (getaddrinfo(bootstrap_hosts[i], "6881", &hints, &res) < 0)
			continue;

		for (cur = res; cur; cur = cur->ai_next)
			udht_add_peer(cur->ai_addr, cur->ai_addrlen);

		freeaddrinfo(res);
	}

	state.bootstrap_added = true;
}

static void udht_peer_timer_cb(struct uloop_timeout *t)
{
	struct peer_entry *p;
	struct sockaddr_in *sin;
	char buf[INET6_ADDRSTRLEN];

	if (list_empty(&bootstrap_peers)) {
		if (!state.peer_count && !state.bootstrap_added)
			udht_add_bootstrap_peer();

		return;
	}

	p = list_first_entry(&bootstrap_peers, struct peer_entry, list);
	list_del(&p->list);
	sin = (struct sockaddr_in *)&p->sa;
	fprintf(stderr, "Ping node %s\n", inet_ntop(sin->sin_family, &sin->sin_addr, buf, sizeof(buf)));
	dht_ping_node((struct sockaddr *)&p->sa, p->sa_len);
	free(p);

	if (state.peer_count++ < 8)
		uloop_timeout_set(t, 2000);
	else
		uloop_timeout_set(t, 15000);
}

void udht_network_add(const uint8_t *auth_key, int seq)
{
	struct network_entry *n;

	list_for_each_entry(n, &networks, list) {
		if (memcmp(n->auth_key, auth_key, sizeof(n->auth_key)) != 0)
			continue;

		goto out;
	}

	n = calloc(1, sizeof(*n));
	n->search_timer.cb = udht_search_timer_cb;
	memcpy(n->auth_key, auth_key, sizeof(n->auth_key));
	udht_id_hash(n->id, n->auth_key, sizeof(n->auth_key));
	list_add_tail(&n->list, &networks);

	if (state.dht_ready)
		uloop_timeout_set(&n->search_timer, 1);

out:
	n->seq = seq;
}

void udht_network_flush(int seq)
{
	struct network_entry *n, *tmp;

	list_for_each_entry_safe(n, tmp, &networks, list) {
		if (seq >= 0 && (n->seq < 0 || n->seq == seq))
			continue;

		list_del(&n->list);
		uloop_timeout_cancel(&n->search_timer);
		free(n);
	}
}


static void
udht_status_check(struct uloop_timeout *t)
{
	int good = 0, dubious = 0, incoming = 0;
	static int prev_good, prev_dubious, prev_incoming;

	state.tick++;
	uloop_timeout_set(t, 1000);

	dht_nodes(AF_INET, &good, &dubious, NULL, &incoming);
	if (good != prev_good || dubious != prev_dubious || incoming != prev_incoming)
		fprintf(stderr, "DHT status: good=%d, dubious=%d, incoming=%d\n", good, dubious, incoming);

	prev_good = good;
	prev_dubious = dubious;
	prev_incoming = incoming;

	if (state.dht_ready)
		return;

	if (good < 4 || good + dubious < 8) {
		if (state.tick > 45 && !state.bootstrap_added)
			udht_add_bootstrap_peer();

		return;
	}

	state.dht_ready = true;
	fprintf(stderr, "DHT is ready\n");
	udht_start_search();
}

static void
udht_load_nodes(const char *filename)
{
	struct blob_attr *data, *cur;
	size_t len;
	FILE *f;
	int rem;

	f = fopen(filename, "r");
	if (!f)
		return;

	data = malloc(sizeof(struct blob_attr));
	if (fread(data, sizeof(struct blob_attr), 1, f) != 1)
		goto out;

	len = blob_pad_len(data);
	if (len <= sizeof(struct blob_attr))
		goto out;

	if (len >= 256 * 1024)
		goto out;

	data = realloc(data, len);
	if (fread(data + 1, len - sizeof(struct blob_attr), 1, f) != 1)
		goto out;

	blob_for_each_attr(cur, data, rem) {
		void *entry = blob_data(cur);

		if (blob_len(cur) == 6) {
			struct sockaddr_in sin = {
				.sin_family = AF_INET,
				.sin_addr = *(struct in_addr *)entry,
				.sin_port = *(uint16_t *)(entry + 4),
			};
			udht_add_peer(&sin, sizeof(sin));
		} else {
			continue;
		}
	}

out:
	free(data);
}

static void
udht_save_nodes(const char *filename)
{
	struct sockaddr_in sin[128];
	struct sockaddr_in6 sin6[128];
	int n_sin = ARRAY_SIZE(sin);
	int n_sin6 = ARRAY_SIZE(sin6);
	FILE *f;
	int i;

	if (!filename)
		return;

	if (dht_get_nodes(sin, &n_sin, sin6, &n_sin6) <= 0)
		return;

	if (n_sin < 8)
		return;

	blob_buf_init(&b, 0);
	for (i = 0; i < n_sin; i++) {
		struct {
			struct in_addr addr;
			uint16_t port;
		} __attribute__((packed)) data = {
			.addr = sin[i].sin_addr,
			.port = sin[i].sin_port,
		};
		blob_put(&b, 4, &data, sizeof(data));
	}

	f = fopen(filename, "w");
	if (!f)
		return;

	fwrite(b.head, blob_pad_len(b.head), 1, f);

	fclose(f);
}

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [<options>] <id string>\n"
		"Options:\n"
		"	-d			Enable debug mode\n"
		"	-n <file>		Set node filename\n"
		"	-N <key>		Add network key\n"
		"\n",
		progname);
	return 1;
}

static void udht_disconnect(struct uloop_timeout *t)
{
	struct peer_entry *p, *tmp;

	if (!udht_connected)
		return;

	list_for_each_entry_safe(p, tmp, &bootstrap_peers, list) {
		list_del(&p->list);
		free(p);
	}

	uloop_timeout_cancel(&disconnect_timer);
	udht_connected = false;
	udht_network_flush(-1);

	uloop_timeout_cancel(&peer_timer);
	uloop_timeout_cancel(&status_timer);
	uloop_timeout_cancel(&periodic_timer);

	udht_save_nodes(node_file);
	dht_uninit();

	memset(&state, 0, sizeof(state));

	udht_close_socket();

#ifndef UBUS_SUPPORT
	uloop_end();
#endif
}

int udht_reconnect(void)
{
	udht_disconnect(&disconnect_timer);

	if (udht_open_socket(unix_path) < 0)
		return -1;

	if (dht_init(dht_unix_fd, -1, local_id, NULL) < 0) {
		udht_close_socket();
		return -1;
	}

	udht_connected = true;
	fprintf(stderr, "DHT connected\n");

	udht_load_nodes(node_file);

	uloop_timeout_set(&peer_timer, 1);
	uloop_timeout_set(&status_timer, 1000);

	return 0;
}

int main(int argc, char **argv)
{
	const char *progname = argv[0];
	uint8_t auth_key[CURVE25519_KEY_SIZE];
	int ch;

	while ((ch = getopt(argc, argv, "dN:n:u:")) != -1) {
		switch (ch) {
		case 'N':
			if (b64_decode(optarg, auth_key, CURVE25519_KEY_SIZE) != CURVE25519_KEY_SIZE) {
				fprintf(stderr, "Invalid network key\n");
				return 1;
			}

			udht_network_add(auth_key, -1);
			break;
		case 'n':
			node_file = optarg;
			break;
		case 'd':
			dht_debug = stderr;
			break;
		case 'u':
			unix_path = optarg;
			break;
		default:
			return usage(progname);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc != 1)
		return usage(progname);

	udht_id_hash(local_id, argv[0], strlen(argv[0]));

	status_timer.cb = udht_status_check;
	periodic_timer.cb = udht_timer_cb;
	peer_timer.cb = udht_peer_timer_cb;
	disconnect_timer.cb = udht_disconnect;
	uloop_init();

#ifdef UBUS_SUPPORT
	udht_ubus_init();
#else
	if (udht_reconnect() < 0) {
		fprintf(stderr, "Failed to connect to unetd\n");
		return 1;
	}
#endif

	uloop_run();
	uloop_done();

	udht_disconnect(&disconnect_timer);
	blob_buf_free(&b);

	return 0;
}
