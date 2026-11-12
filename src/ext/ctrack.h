/*
 * Userspace conntrack of the extensions (docs/EXT_ROADMAP.md, 4.2; D1-D8,
 * E8): a port of zapret2's nfq2/conntrack.c with its semantics, so that
 * positions and ranges mean here what they mean in nfqws2.
 *
 * A flow is keyed by its 5-tuple as the client sent it: the client is the
 * side of the SYN (or the receiver of a SYN+ACK seen first), for UDP the
 * side of the first datagram. Only a SYN, a SYN+ACK or a UDP datagram opens
 * a flow; other TCP packets of unknown flows are not tracked. Per side it
 * counts packets (n), packets with data (d) and data bytes (b, with
 * retransmissions), and for TCP keeps seq0, the last seq, the position
 * after the data, the highest position (retransmissions), window, scale and
 * MSS. A SYN on a flow past the SYN stage starts it over, as does a SYN+ACK
 * with another ISN.
 *
 * Timeouts per state (SYN, ESTABLISHED, FIN, UDP; zapret2's 60:300:60:60)
 * are applied every 10 s of packet time. The table holds at most max flows:
 * a new flow then evicts the least recently active one (zapret2 has no
 * limit). An ICMP error (unreachable, time exceeded, parameter problem,
 * packet too big, redirect) belongs to the flow of the packet it carries.
 *
 * One table per engine worker; not thread-safe.
 */
#ifndef GENEVA_EXT_CTRACK_H
#define GENEVA_EXT_CTRACK_H

#include <stddef.h>
#include <stdint.h>

#include "pkt.h"
#include "range.h"

enum { CT_SYN = 0, CT_EST, CT_FIN };

#define CT_XSTATE 32   /* per-flow state bytes of the x-actions (D8) */
#define CT_MAX_TREES 64 /* trees of one forest that can be cut off per flow */
#define CT_DEFAULT_MAX 16384
#define CT_DEFAULT_MSS 1220 /* zapret2's DEFAULT_MSS */

typedef struct {
    uint64_t pcounter, pdcounter, pbcounter; /* n, d, b */
    uint32_t ip6flow;
    /* TCP only */
    uint32_t pos;        /* seq_last + data length; for the reverse side, the ack */
    uint32_t uppos;      /* highest position seen: retransmissions */
    uint32_t uppos_prev; /* the one before */
    uint32_t seq_last, seq0;
    uint16_t winsize, mss;
    uint32_t winsize_calc;
    uint8_t scale;
    uint8_t rseq_over_2g;
} ct_side;

typedef struct ct_flow ct_flow;
struct ct_flow {
    /* key: the client's packet */
    uint8_t ver, proto;
    uint8_t cli[16], srv[16];
    uint16_t cport, sport;

    ct_side client, server;
    uint8_t state; /* CT_* */
    uint8_t incoming_ttl;
    uint32_t ttl_put; /* the second the ipcache last got incoming_ttl */
    uint64_t t_start, t_last; /* ms */

    /* D7: trees cut off for good on this flow, per forest (out, in), and
     * whether every tree of a forest is */
    uint64_t tree_cut[2];
    uint8_t all_cut[2];
    int cut_serial; /* the strategy the bits are about (strategy.serial) */
    uint8_t xstate[CT_XSTATE]; /* D8, zeroed with the flow */
    /* L7 of the extensions (src/ext/xl7.c): the flow's protocol (L7_*, 0:
     * not known yet), its host name and a reassembly in progress; freed
     * through ct_config.clear */
    uint8_t l7proto;
    char *host;
    void *xr;
    /* the x-actions' per-flow state (src/ext/xact.c), freed through
     * ct_config.clear */
    void *xa;
    /* seqtrack (src/ext/seqtrack.c): the shift of a grown first message,
     * freed through ct_config.clear */
    void *xseq;
    /* its profile (src/ext/profile.c): the index, -1 for none; looked for
     * xprof_done times (0: not yet), the last time with the L7 protocol
     * xprof_l7 and (xprof_host) the host name */
    int16_t xprof;
    uint8_t xprof_done, xprof_l7, xprof_host;
    /* zapret2's ctrack->hostname (src/ext/ext.c, autolist.c): the host name
     * without its port, found by the L7 (chost_disc) or taken from the
     * ipcache; the profile's hostlist check (xcheck: 0 not done, 1 passed,
     * 2 failed: no strategy) and the autolist's watch (ah_check: watched,
     * ah_final: decided, ah_retrans: the retransmission counter) */
    char *chost;
    uint8_t chost_ip, chost_disc, xcheck, ah_check, ah_final, ah_retrans;
    /* the surgical path (src/ext/ext.c, X10b): the engine let the
     * connection go (its verdicts mark it, the rules stop queueing it):
     * how many verdicts marked it */
    uint8_t xhealthy;
    /* the tuner (src/ext/tuner.c, X11): zapret2's per-connection record of
     * circular (crec: nocheck, failure, retrans) */
    uint8_t xt_nocheck, xt_failure;
    uint16_t xt_retrans;

    /* table links */
    ct_flow *hnext, *lprev, *lnext;
    uint32_t hash;
};

typedef struct {
    uint32_t t_syn, t_est, t_fin, t_udp; /* seconds */
    size_t max;
    /* called before a flow is started over or freed: frees what its
     * pointers hold (NULL: nothing to free); ud is clear_ud */
    void (*clear)(ct_flow *f, void *ud);
    void *clear_ud;
} ct_config;

void ct_config_default(ct_config *c);
/* "S:E:F[:U]" as zapret2's --ctrack-timeouts. Returns 0 or -1. */
int ct_timeouts_parse(const char *s, ct_config *c);

typedef struct ctrack ctrack;

ctrack *ctrack_new(const ct_config *c);
void ctrack_free(ctrack *t);
size_t ctrack_count(const ctrack *t);
uint64_t ctrack_evictions(const ctrack *t);

/* Feeds p (ConntrackPoolFeed) at time now (ms). Returns its flow, or NULL
 * when it has none; *reverse is 1 when p comes from the server. An ICMP
 * error is not counted and changes nothing: it returns the flow of the
 * packet it carries, and *reverse as for a reply to that packet (1 when the
 * client sent it, since the ICMP travels back towards the client) (E8). */
ct_flow *ctrack_feed(ctrack *t, const gpkt *p, uint64_t now, int *reverse);
/* Finds p's flow without changing anything (ConntrackPoolDoubleSearch). */
ct_flow *ctrack_find(ctrack *t, const gpkt *p, int *reverse);
/* Calls fn for every flow, the least recently active first; fn must not
 * feed or purge t. */
void ctrack_foreach(ctrack *t, void (*fn)(ct_flow *f, void *ud), void *ud);
/* Purges expired flows now (also done by feed every 10 s). */
void ctrack_purge(ctrack *t, uint64_t now);

/* Is the last packet of this side a retransmission (zapret2's
 * is_retransmission: uppos_prev >= pos)? */
int ct_is_retrans(const ct_side *s);
/* The MSS for generated segments: the smaller of the two sides', or
 * CT_DEFAULT_MSS when one is unknown (D5). */
unsigned ct_mss(const ct_flow *f);
/* The counters of a side as ranges see them. */
void ct_view(const ct_side *s, xside_view *v);

#endif
