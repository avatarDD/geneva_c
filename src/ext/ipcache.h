/*
 * The IP cache of the extensions (docs/EXT_ROADMAP.md, C6, E6): zapret2's
 * ipcache (nfq2/pools.c, desync.c). Per address (and interface) it keeps
 *
 *   - a host name: from DNS answers (A, AAAA) seen in captured traffic and
 *     from the flows whose name became known, so that a flow to that
 *     address knows its host before its first data (--ext-ipcache-hostname);
 *   - the TTL of the server's first reply, per interface, so that autottl
 *     works on the first packet of the next flow.
 *
 * An entry lives --ext-ipcache-lifetime seconds after it was last written
 * (7200; 0: for ever). Times are the caller's (the packet's, for apply).
 * One cache per process; not thread-safe (the engine holds its lock).
 */
#ifndef GENEVA_EXT_IPCACHE_H
#define GENEVA_EXT_IPCACHE_H

#include <stddef.h>
#include <stdint.h>

#define XIPC_LIFETIME 7200

void xipc_config(unsigned lifetime_s, int hostname);
int xipc_hostname_on(void);
/* Drops every entry (and goes back to the default configuration) */
void xipc_reset(void);
/* --ext-workers: from now on every call takes a lock (call before the
 * threads start) */
void xipc_threads(void);
size_t xipc_count(void);

/* ver 4 or 6, a its 4 or 16 bytes; iface NULL or "" for none */
void xipc_put_host(int ver, const uint8_t *a, const char *host, int is_ip, uint64_t now_ms);
/* 1 with the name in out (cap bytes) and *is_ip, 0 when none (or the
 * host names are not cached) */
int xipc_get_host(int ver, const uint8_t *a, char *out, size_t cap, int *is_ip);
void xipc_put_ttl(int ver, const uint8_t *a, const char *iface, uint8_t ttl, uint64_t now_ms);
/* 0 when not known */
uint8_t xipc_get_ttl(int ver, const uint8_t *a, const char *iface);

/* Expired entries out; at most once a second of now_ms */
void xipc_purge(uint64_t now_ms);

/* zapret2's feed_dns_response: the addresses of the A and AAAA answers of
 * a DNS response (one question, A or AAAA) get its name. Returns how many,
 * -1 when it is not such a response. */
int xipc_dns_response(const uint8_t *d, size_t n, uint64_t now_ms);

#endif
