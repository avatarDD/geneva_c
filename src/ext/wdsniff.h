/*
 * The observation plane of --ext-auto on Windows (docs/EXT.md, X9c): a
 * WinDivert handle with the SNIFF and RECV_ONLY flags gets a copy of every
 * packet of the PC (loopback aside) and diverts nothing. It is opened at a
 * priority above the engine's handle, so it sees the packets as they were
 * before the strategy, like NFLOG's chains on Linux (src/ext/nflog.c).
 *
 * A receiver thread copies each packet (cut to range bytes) into a ring and
 * wakes the main loop through a loopback UDP socket; the main loop drains
 * the ring. A full ring drops copies, never traffic: they are counted.
 */
#ifndef GENEVA_EXT_WDSNIFF_H
#define GENEVA_EXT_WDSNIFF_H

#include <stddef.h>
#include <stdint.h>

#include "plat.h"
#include "util.h"

typedef struct wdsniff wdsniff;

/* The WinDivert filter of the handle */
#define WDSNIFF_FILTER "!loopback and (tcp or udp or icmp or icmpv6)"

/* Opens the handle at priority (-30000..30000) copying range bytes of each
 * packet. Returns NULL with a message in err (and *priv set when the
 * process lacks the rights). Not on other systems. */
wdsniff *wdsniff_open(int priority, uint32_t range, sbuf *err, int *priv);
void wdsniff_close(wdsniff *s);
/* the socket to poll for POLLIN */
sock_t wdsniff_fd(const wdsniff *s);

/* Calls cb for up to max packets of the ring (out: 1 outbound). Returns the
 * number, or -1 when the receiver failed. Copies the full ring dropped are
 * added to *lost. */
typedef void (*wdsniff_cb)(const uint8_t *data, size_t len, int out, void *ctx);
int wdsniff_read(wdsniff *s, size_t max, wdsniff_cb cb, void *ctx, uint64_t *lost);

#endif
