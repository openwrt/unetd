// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2025 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_TOKEN_H
#define __UNETD_TOKEN_H

void *token_create(struct network *net, struct network_host *target,
		   const char *service, struct blob_attr *info, size_t *len);
bool token_parse(struct blob_buf *buf, const char *token);

#endif
