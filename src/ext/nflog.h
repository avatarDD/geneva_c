/*
 * NFLOG over raw netlink (Linux; docs/EXT_ROADMAP.md, 4.4): the
 * observation plane of --ext-auto. The firewall copies the first packets of
 * every flow (and the ICMP errors) to a log group; the kernel does not wait
 * for us, so a slow reader loses copies, never traffic.
 */
#ifndef GENEVA_EXT_NFLOG_H
#define GENEVA_EXT_NFLOG_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef struct nflog nflog;

typedef struct {
    uint8_t hook;           /* NF_INET_* as in the packet header */
    uint32_t mark;
    uint32_t indev, outdev; /* interface indexes, 0 if unknown */
    const char *prefix;     /* the rule's prefix ("" without one) */
    const uint8_t *data;    /* the IP packet, cut to the copy range */
    size_t len;
} nflog_msg;

/* Binds log group (0..65535) copying range bytes of each packet. Returns
 * NULL with a message in err. */
nflog *nflog_open(uint16_t group, uint32_t range, int rcvbuf, sbuf *err);
void nflog_close(nflog *l);
int nflog_fd(const nflog *l);

typedef void (*nflog_cb)(const nflog_msg *m, void *ctx);
/* Reads one datagram (non-blocking) and calls cb for every packet in it.
 * Returns the number of packets, 0 if nothing was ready, -1 on a fatal
 * error. Copies the kernel dropped (ENOBUFS) are counted in *lost. */
int nflog_read(nflog *l, nflog_cb cb, void *ctx, uint64_t *lost);

/* For tests: the packets of one datagram in buf. */
int nflog_parse(const uint8_t *buf, size_t n, nflog_cb cb, void *ctx);

#endif
