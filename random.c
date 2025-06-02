// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Felix Fietkau <nbd@nbd.name>
 */
#ifdef linux
#include <sys/random.h>
#endif
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "random.h"

static ssize_t __getrandom(void *buf, size_t buflen)
{
	static FILE *urandom;
	ssize_t ret;

#ifdef linux
	ret = getrandom(buf, buflen, 0);
	if (ret > 0)
		return ret;
#endif

#ifdef __APPLE__
	arc4random_buf(buf, buflen);
	return buflen;
#endif

	if (!urandom) {
		urandom = fopen("/dev/urandom", "r");
		if (!urandom)
			abort();
	}

	ret = fread(buf, buflen, 1, urandom);
	if (ret != 1)
		return -1;

	return buflen;
}

void randombytes(void *buf, size_t len)
{
	while (len > 0) {
		ssize_t cur = len;

		if (cur > 256)
			cur = 256;

		cur = __getrandom(buf, cur);
		if (cur < 0)
			continue;

		buf += cur;
		len -= cur;
	}
}
