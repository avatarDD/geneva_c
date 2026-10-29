/*
 * NFQUEUE over raw netlink (Linux), without libnetfilter_queue or libmnl.
 *
 * One handle binds one queue number. Packets arrive as nfq_msg records;
 * every packet must get exactly one verdict, possibly later (the kernel keeps
 * the packet until then, which is how delayed sends keep their exact bytes).
 */
#ifndef GENEVA_NFQ_H
#define GENEVA_NFQ_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

/* netfilter hooks, as reported in the packet header */
enum {
    NFQ_HOOK_PRE_ROUTING = 0,
    NFQ_HOOK_LOCAL_IN = 1,
    NFQ_HOOK_FORWARD = 2,
    NFQ_HOOK_LOCAL_OUT = 3,
    NFQ_HOOK_POST_ROUTING = 4,
};

enum { NFQ_DROP = 0, NFQ_ACCEPT = 1 };

typedef struct nfq nfq;

typedef struct {
    uint32_t id;
    uint16_t hw_proto; /* ethertype, host order */
    uint8_t hook;
    uint32_t mark;
    uint32_t indev, outdev; /* interface indexes, 0 if unknown */
    const uint8_t *data;    /* the IP packet */
    size_t len;
} nfq_msg;

typedef struct {
    uint16_t queue;
    uint32_t maxlen;  /* kernel queue length (packets) */
    int fail_open;    /* accept instead of drop when the queue is full */
    int rcvbuf;       /* socket receive buffer, bytes (0 = default) */
} nfq_config;

/* Binds the queue. On failure returns NULL, sets *errnum to the errno and
 * writes a message to err. */
nfq *nfq_open(const nfq_config *cfg, int *errnum, sbuf *err);
void nfq_close(nfq *q);
int nfq_fd(const nfq *q);

typedef void (*nfq_cb)(const nfq_msg *m, void *ctx);
/* Reads one datagram (non-blocking) and calls cb for every packet in it.
 * Returns the number of packets, 0 if nothing was ready, -1 on a fatal
 * error. A receive buffer overrun (ENOBUFS) is counted in *dropped and is
 * not fatal. */
int nfq_read(nfq *q, nfq_cb cb, void *ctx, uint64_t *dropped);
/* Gives a verdict. data/len replace the packet when data != NULL. Mark is
 * set when set_mark != 0. Returns 0 or -1 (errno set). */
int nfq_verdict(nfq *q, uint32_t id, int verdict, const uint8_t *data, size_t len, int set_mark,
                uint32_t mark);

#endif
