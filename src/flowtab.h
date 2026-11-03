/*
 * Flow table for --first N where no conntrack does it (Windows): which
 * packets of a TCP or UDP flow are among its first N in their direction.
 *
 * A flow is a 5-tuple normalized by direction: the local address and port
 * (the source of outbound packets, the destination of inbound ones) first,
 * so a packet and its reply share one flow. Each flow counts its outbound
 * and inbound packets separately.
 *
 * Lifetime: a TCP flow ends 10 s after FIN went both ways or after a RST
 * (either way), otherwise after 300 s without packets; a UDP flow after 60 s
 * without packets. An expired flow seen again starts over. The table holds
 * at most max flows: a new flow then evicts the least recently active one.
 *
 * Not thread-safe: the engine calls it under its lock.
 */
#ifndef GENEVA_FLOWTAB_H
#define GENEVA_FLOWTAB_H

#include <stddef.h>
#include <stdint.h>

#include "pkt.h"
#include "strategy.h"

#define FLOW_MAX 65536
#define FLOW_TCP_IDLE_MS 300000
#define FLOW_UDP_IDLE_MS 60000
#define FLOW_CLOSED_MS 10000

typedef struct flowtab flowtab;

flowtab *flowtab_new(size_t max);
void flowtab_free(flowtab *t);

/* Counts packet p going in direction dir at time now (ms). Returns 1 when it
 * is among the first `first` packets of its flow in that direction (the
 * strategy applies), 0 when it is past them. Packets without TCP or UDP
 * (ICMP, later IP fragments) have no flow: always 1. *evicted is set when a
 * flow was pushed out to make room. */
int flowtab_packet(flowtab *t, const gpkt *p, strat_dir dir, uint32_t first, uint64_t now, int *evicted);

/* Removes expired flows; returns how many. */
size_t flowtab_expire(flowtab *t, uint64_t now);

size_t flowtab_count(const flowtab *t);

/* The packet counts of p's flow (out, in), for tests. Returns 0 when there
 * is no live flow. */
int flowtab_peek(const flowtab *t, const gpkt *p, strat_dir dir, uint64_t now, uint32_t *out, uint32_t *in);

#endif
