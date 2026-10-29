/*
 * Sending finished IP packets through raw sockets (Linux). Packets carry a
 * firewall mark so that the engine's own rules skip them.
 *
 * Linux rewrites the IPv4 total length and header checksum of raw packets
 * (and fills in an IP ID of 0), so the engine prefers the NFQUEUE verdict
 * path, which keeps every byte, and uses raw sends only for extra packets.
 */
#ifndef GENEVA_RAWSEND_H
#define GENEVA_RAWSEND_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef struct rawsend rawsend;

/* Opens IPv4 and (if available) IPv6 raw sockets. Returns NULL with a
 * message in err when no socket could be opened. */
rawsend *rawsend_open(uint32_t mark, sbuf *err);
void rawsend_close(rawsend *r);
/* Sends one IP packet. Returns 0 or -1 (errno set). */
int rawsend_send(rawsend *r, const uint8_t *pkt, size_t len);

#endif
