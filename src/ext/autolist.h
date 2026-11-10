/*
 * The autolist of the extensions (docs/EXT_ROADMAP.md, C5): zapret2's
 * --hostlist-auto (nfq2/desync.c auto_hostlist_*, process_retrans_fail,
 * process_udp_fail and the incoming checks). A flow of a profile with an
 * autolist whose host is not in the profile's lists (and not excluded) is
 * watched until its outcome is known:
 *
 *   TCP fails  - the client sends its request retrans-threshold times
 *                within the first retrans-maxseq bytes (then, with
 *                retrans-reset, the client gets a RST); the server answers
 *                within incoming-maxseq bytes with a RST or an HTTP
 *                redirect to another domain;
 *   TCP works  - the client goes past retrans-maxseq or the server past
 *                incoming-maxseq;
 *   UDP fails  - udp-out packets out with at most udp-in back;
 *   UDP works  - more than udp-in back.
 *
 * fail-threshold failures of a host within fail-time seconds add it to the
 * autolist (in memory and a line in its file); a working flow resets the
 * host's count. Not in --server-side (zapret2: not in server mode).
 */
#ifndef GENEVA_EXT_AUTOLIST_H
#define GENEVA_EXT_AUTOLIST_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "pkt.h"

#define XAH_FAIL_THRESHOLD 3
#define XAH_FAIL_TIME 60
#define XAH_RETRANS_THRESHOLD 3
#define XAH_RETRANS_MAXSEQ 32768
#define XAH_INCOMING_MAXSEQ 4096
#define XAH_UDP_OUT 4
#define XAH_UDP_IN 1

#define XAH_RETRANS_STOP 255

typedef struct xahfail {
    char *host;
    int counter;
    uint64_t expire; /* seconds */
} xahfail;

/* --hostlist-auto-debug FILE (all profiles); NULL: off. Returns 0 or -1
 * when the file cannot be created. */
int xah_debug_log(const char *path);

/* What the detection needs about a packet */
typedef struct {
    const gpkt *p;
    ct_flow *f;
    int reverse;      /* from the server */
    int l7p;          /* L7P_* of the packet */
    const uint8_t *payload;
    size_t len;
    uint64_t now_ms;
    /* sends a RST to the client (NULL: none) */
    void (*send)(void *ud, const uint8_t *pkt, size_t len);
    void *ud;
} xah_pkt;

#include "profile.h"

void xah_free(xprofile *p);
/* auto_hostlist_failed, auto_hostlist_reset_fail_counter */
void xah_failed(xprofile *p, const char *host, int host_ip, const char *client, int l7, uint64_t now_ms);
void xah_reset(xprofile *p, const char *host, const char *client, int l7);
/* HostFailPoolPurgeRateLimited */
void xah_purge(xprofile *p, uint64_t now_ms);

/* The flow's host is f->chost (set by the caller with f->ah_check). TCP:
 * before the profile is looked for again (the server's answers, the
 * client's retransmissions); UDP: after (the counts) */
void xah_tcp(xprofile *p, const xah_pkt *k);
void xah_udp(xprofile *p, const xah_pkt *k);

/* zapret2's RST to the retransmitter: a RST from the server to the client
 * of TCP packet p (from the client) into out (60 bytes). Returns its
 * length, 0 when p is not TCP. */
size_t xah_rst(const gpkt *p, const ct_flow *f, uint8_t *out);

#endif
