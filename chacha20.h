// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2022 Felix Fietkau <nbd@nbd.name>
 */
#ifndef __UNETD_CHACHA20_H
#define __UNETD_CHACHA20_H

#define CHACHA20_NONCE_SIZE	8
#define CHACHA20_KEY_SIZE	32

void chacha20_encrypt_msg(void *msg, size_t len, const void *nonce, const void *key);

#endif
