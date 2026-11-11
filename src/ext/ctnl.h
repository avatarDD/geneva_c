/*
 * ctnetlink (Linux; docs/EXT_ROADMAP.md, 4.4): the kernel conntrack's
 * counters of single flows for --ext-auto. A request asks for one flow by
 * its original tuple; the answers come back on the socket in any order
 * and are matched by their tuple (an answer that the flow is gone, by the
 * request's sequence number). The counters need nf_conntrack_acct, which
 * the observation rules (ct packets, connbytes) turn on.
 */
#ifndef GENEVA_EXT_CTNL_H
#define GENEVA_EXT_CTNL_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef struct {
    uint8_t ver, proto; /* 4 or 6; 6 or 17 */
    uint8_t src[16], dst[16];
    uint16_t sport, dport;
} ctnl_tuple;

typedef struct {
    ctnl_tuple t;     /* the original tuple */
    int found;        /* 0: the kernel has no such flow (any more) */
    uint8_t tcp_state; /* TCP_CONNTRACK_*: 3 established, 4.. closing, 0 unknown */
    uint64_t opackets, obytes, rpackets, rbytes;
} ctnl_entry;

#define CTNL_TCP_ESTABLISHED 3

typedef void (*ctnl_cb)(const ctnl_entry *e, void *ctx);

typedef struct ctnl ctnl;

/* Returns NULL with a message in err */
ctnl *ctnl_open(sbuf *err);
void ctnl_close(ctnl *c);
int ctnl_fd(const ctnl *c);
/* Asks for one flow (non-blocking). Returns 0, or -1 when the socket is
 * full (try again later). */
int ctnl_request(ctnl *c, const ctnl_tuple *t);
/* Reads one datagram (non-blocking) and calls cb for every answer in it.
 * Returns the number of answers, 0 when nothing was ready, -1 on a fatal
 * error. */
int ctnl_read(ctnl *c, ctnl_cb cb, void *ctx);

/* For tests: the request message for t with sequence number seq into buf
 * (cap bytes, at least 128); its length. */
size_t ctnl_build_get(uint8_t *buf, size_t cap, const ctnl_tuple *t, uint32_t seq);
/* The answers of one datagram; an error answer's tuple comes from
 * lookup(seq) (NULL: dropped). */
int ctnl_parse(const uint8_t *buf, size_t n, const ctnl_tuple *(*lookup)(uint32_t seq, void *ctx), ctnl_cb cb,
               void *ctx);

#endif
