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

/* --ext (docs/EXT_ROADMAP.md, A7), as nfqws2 sends: sockets opened after
 * this get SO_PRIORITY 6 and IP_FREEBIND/IPV6_FREEBIND; with bind-fix for
 * a family, rawsend_send_x() binds the socket to the packet's interface
 * (SO_BINDTODEVICE), since Linux may pick a wrong one when ip rules
 * exist. */
enum { RAWSEND_EXT = 1, RAWSEND_BIND4 = 2, RAWSEND_BIND6 = 4 };
void rawsend_set_flags(unsigned flags);
/* rawsend_send() with mark bits added to the socket's mark and ifout (NULL
 * or "": none) for bind-fix. */
int rawsend_send_x(rawsend *r, const uint8_t *pkt, size_t len, uint32_t mark, const char *ifout);

#endif
