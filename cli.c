// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <libubox/utils.h>
#include "edsign.h"
#include "ed25519.h"
#include "curve25519.h"
#include "auth-data.h"

static uint8_t pubkey[EDSIGN_PUBLIC_KEY_SIZE];
static uint8_t seckey[EDSIGN_PUBLIC_KEY_SIZE];
static FILE *out_file;
static enum {
	CMD_UNKNOWN,
	CMD_GENERATE,
	CMD_PUBKEY,
	CMD_HOST_PUBKEY,
	CMD_VERIFY,
	CMD_SIGN,
} cmd;

static void print_key(const uint8_t *key)
{
	char keystr[B64_ENCODE_LEN(EDSIGN_PUBLIC_KEY_SIZE)];

	if (b64_encode(key, EDSIGN_PUBLIC_KEY_SIZE, keystr, sizeof(keystr)) < 0)
		return;

	fprintf(out_file, "%s\n", keystr);
}

static int usage(const char *progname)
{
	fprintf(stderr, "Usage: %s [command|options] [<file>]\n"
		"Commands:\n"
		"	-S			Sign file\n"
		"	-V			Verify file\n"
		"	-P			Get pulic signing key from secret key\n"
		"	-H			Get pulic host key from secret key\n"
		"	-G			Generate new private key\n"
		"\n"
		"Options:\n"
		"	-o <file>:		Set output file to <file> (defaults to stdout)\n"
		"	-k <keyfile>|-:		Set public key from file or stdin\n"
		"	-K <keyfile>|-:		Set secret key from file or stdin\n"
		"\n", progname);
	return 1;
}

static int cmd_sign(int argc, char **argv)
{
	struct unet_auth_hdr hdr = {
		.magic = cpu_to_be32(UNET_AUTH_MAGIC),
	};
	struct unet_auth_data *data;
	struct timeval tv;
	struct stat st;
	off_t len;
	FILE *f;

	if (argc != 1) {
		fprintf(stderr, "Missing filename\n");
		return 1;
	}

	if (gettimeofday(&tv, NULL)) {
		perror("gettimeofday");
		return 1;
	}

	if (stat(argv[0], &st) ||
	    (f = fopen(argv[0], "r")) == NULL) {
		fprintf(stderr, "Input file not found\n");
		return 1;
	}

	data = calloc(1, sizeof(*data) + st.st_size + 1);
	data->timestamp = cpu_to_be64(tv.tv_sec);
	len = fread(data + 1, 1, st.st_size, f);
	fclose(f);

	if (len != st.st_size) {
		fprintf(stderr, "Error reading from input file\n");
		return 1;
	}

	len += sizeof(*data);

	memcpy(data->pubkey, pubkey, sizeof(pubkey));
	edsign_sign(hdr.signature, pubkey, seckey, (const void *)data, len);

	fwrite(&hdr, sizeof(hdr), 1, out_file);
	fwrite(data, len, 1, out_file);

	free(data);

	return 0;
}

static int cmd_verify(int argc, char **argv)
{
	struct unet_auth_data *data;
	struct unet_auth_hdr *hdr;
	struct stat st;
	off_t len;
	FILE *f;
	int ret = 1;

	if (argc != 1) {
		fprintf(stderr, "Missing filename\n");
		return 1;
	}

	if (stat(argv[0], &st) ||
	    (f = fopen(argv[0], "r")) == NULL) {
		fprintf(stderr, "Input file not found\n");
		return 1;
	}

	if (st.st_size <= sizeof(*hdr) + sizeof(*data)) {
		fprintf(stderr, "Input file too small\n");
		fclose(f);
		return 1;
	}

	hdr = calloc(1, st.st_size);
	len = fread(hdr, 1, st.st_size, f);
	fclose(f);

	if (len != st.st_size) {
		fprintf(stderr, "Error reading from input file\n");
		return 1;
	}

	ret = unet_auth_data_validate(pubkey, hdr, len, NULL);
	switch (ret) {
	case -1:
		fprintf(stderr, "Invalid input data\n");
		break;
	case -2:
		fprintf(stderr, "Public key does not match\n");
		break;
	case -3:
		fprintf(stderr, "Signature verification failed\n");
		break;
	}

	free(hdr);
	return ret;
}

static int cmd_host_pubkey(int argc, char **argv)
{
	curve25519_generate_public(pubkey, seckey);
	print_key(pubkey);

	return 0;
}

static int cmd_pubkey(int argc, char **argv)
{
	print_key(pubkey);

	return 0;
}

static int cmd_generate(int argc, char **argv)
{
	FILE *f;
	int ret;

	f = fopen("/dev/urandom", "r");
	if (!f) {
		fprintf(stderr, "Can't open /dev/urandom\n");
		return 1;
	}

	ret = fread(seckey, sizeof(seckey), 1, f);
	fclose(f);

	if (ret != 1) {
		fprintf(stderr, "Can't read data from /dev/urandom\n");
		return 1;
	}

	ed25519_prepare(seckey);
	print_key(seckey);

	return 0;
}

static bool parse_key(uint8_t *dest, const char *str)
{
	char keystr[B64_ENCODE_LEN(EDSIGN_PUBLIC_KEY_SIZE) + 2];
	FILE *f;
	int len;

	if (!strcmp(str, "-"))
		f = stdin;
	else
		f = fopen(str, "r");

	if (!f) {
		fprintf(stderr, "Can't open key file for reading\n");
		return false;
	}

	len = fread(keystr, 1, sizeof(keystr) - 1, f);
	if (f != stdin)
		fclose(f);

	keystr[len] = 0;

	if (b64_decode(keystr, dest, EDSIGN_PUBLIC_KEY_SIZE) != EDSIGN_PUBLIC_KEY_SIZE) {
		fprintf(stderr, "Failed to parse key data\n");
		return false;
	}

	return true;
}

static bool cmd_needs_pubkey(void)
{
	switch (cmd) {
	case CMD_VERIFY:
		return true;
	default:
		return false;
	}
}

static bool cmd_needs_key(void)
{
	switch (cmd) {
	case CMD_SIGN:
	case CMD_PUBKEY:
	case CMD_HOST_PUBKEY:
		return true;
	default:
		return false;
	}
}

int main(int argc, char **argv)
{
	const char *progname = argv[0];
	const char *out_filename = NULL;
	bool has_key = false, has_pubkey = false;
	int ret, ch;

	while ((ch = getopt(argc, argv, "o:k:K:GHPSV")) != -1) {
		switch (ch) {
		case 'o':
			out_filename = optarg;
			break;
		case 'k':
			if (has_pubkey)
				return usage(progname);

			if (!parse_key(pubkey, optarg)) {
				return 1;
			}

			has_pubkey = true;
			break;
		case 'K':
			if (has_pubkey)
				return usage(progname);

			if (!parse_key(seckey, optarg)) {
				return 1;
			}

			has_key = true;

			edsign_sec_to_pub(pubkey, seckey);
			has_pubkey = true;
			break;
		case 'G':
			if (cmd != CMD_UNKNOWN)
				return usage(progname);

			cmd = CMD_GENERATE;
			break;
		case 'S':
			if (cmd != CMD_UNKNOWN)
				return usage(progname);

			cmd = CMD_SIGN;
			break;
		case 'P':
			if (cmd != CMD_UNKNOWN)
				return usage(progname);

			cmd = CMD_PUBKEY;
			break;
		case 'H':
			if (cmd != CMD_UNKNOWN)
				return usage(progname);

			cmd = CMD_HOST_PUBKEY;
			break;
		case 'V':
			if (cmd != CMD_UNKNOWN)
				return usage(progname);

			cmd = CMD_VERIFY;
			break;
		default:
			return usage(progname);
		}
	}

	if (!has_key && cmd_needs_key()) {
		fprintf(stderr, "Missing -K <key> argument\n");
		return 1;
	}

	if (!has_pubkey && cmd_needs_pubkey()) {
		fprintf(stderr, "Missing -k <key> argument\n");
		return 1;
	}

	argc -= optind;
	argv += optind;

	if (out_filename) {
		out_file = fopen(out_filename, "w");
		if (!out_file) {
			fprintf(stderr, "Failed to open output file\n");
			return 1;
		}
	} else {
		out_file = stdout;
	}

	ret = -1;
	switch (cmd) {
	case CMD_GENERATE:
		ret = cmd_generate(argc, argv);
		break;
	case CMD_SIGN:
		ret = cmd_sign(argc, argv);
		break;
	case CMD_PUBKEY:
		ret = cmd_pubkey(argc, argv);
		break;
	case CMD_HOST_PUBKEY:
		ret = cmd_host_pubkey(argc, argv);
		break;
	case CMD_VERIFY:
		ret = cmd_verify(argc, argv);
		break;
	case CMD_UNKNOWN:
		ret = usage(progname);
		break;
	}

	if (out_file != stdout) {
		fclose(out_file);
		if (ret)
			unlink(out_filename);
	}

	return ret;
}
