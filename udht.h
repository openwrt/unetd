#ifndef __UDHT_H
#define __UDHT_H

int udht_reconnect(void);
void udht_network_add(const uint8_t *auth_key, int seq);
void udht_network_flush(int seq);

#ifdef UBUS_SUPPORT
void udht_ubus_init(void);
#else
static inline void udht_ubus_init(void)
{
}
#endif


#endif
