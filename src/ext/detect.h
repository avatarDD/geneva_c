/*
 * The detector of --ext-auto (docs/EXT_ROADMAP.md, 4.4; C5, E7, K3, K4):
 * what the observation plane sees of a flow (the first packets of each
 * direction and the ICMP errors, src/ext/nflog.c) gives the flow an
 * outcome, and the outcomes of a key's flows decide whether the key is
 * impaired and by what.
 *
 * Flow classes (zapret2's standard_failure_detector and the autolist's
 * checks with their thresholds, then the extensions):
 *
 *   RETRANS        the client sends its data again retrans (3) times within
 *                  the first retrans_maxseq (32768) bytes
 *   RST_IN         a RST from the server within incoming_maxseq (4096)
 *                  before any data from it (zapret2 takes one after the
 *                  data too: a short exchange that ends with a RST)
 *   RST_INJECT     a RST within incoming_maxseq whose TTL differs from the
 *                  SYN,ACK's by rst_ttl_delta (2) or more: injected
 *   REDIRECT       an HTTP 302/307 to another domain within incoming_maxseq
 *   UDP_NOANSWER   udp_out (4) datagrams out and at most udp_in (1) back
 *   BLACKHOLE_SYN  syn_tries (2) SYNs without a SYN,ACK
 *   ICMP_PROHIBIT  ICMP unreachable 9, 10 or 13 (ICMPv6 1/1) for the flow
 *
 * Success (standard_success_detector): the client past retrans_maxseq or
 * the server past incoming_maxseq; UDP: more than udp_in back. A flow gets
 * one outcome; one that ends undecided gets none.
 *
 * Keys: the flow's protocol and port ("tcp/443"), the server's network
 * (/24, IPv6 /48), its address and its host name (from the flow's
 * ClientHello or HTTP request, else the address cache). Each key runs
 * Wald's sequential test on its outcomes: a failure moves it towards
 * "impaired" (failure rate p1, 0.6), a success towards "healthy" (p0, 0.1),
 * at error rates alpha = beta = 0.05; two failures in a row decide a
 * fresh key. The key's class is the commonest class of its failures.
 *
 * Pure: packets and times in, events out through the sink. One instance
 * per observer; not thread-safe.
 */
#ifndef GENEVA_EXT_DETECT_H
#define GENEVA_EXT_DETECT_H

#include <stddef.h>
#include <stdint.h>

#include "ctrack.h"
#include "json.h"
#include "pkt.h"

enum {
    XC_NONE = 0,
    XC_RETRANS,
    XC_RST_IN,
    XC_RST_INJECT,
    XC_REDIRECT,
    XC_UDP_NOANSWER,
    XC_BLACKHOLE_SYN,
    XC_ICMP_PROHIBIT,
    XC_N
};
const char *xdet_class_name(int c);

enum { XK_PORT = 0, XK_NET, XK_IP, XK_HOST, XK_LEVELS };
const char *xdet_level_name(int level);

typedef struct {
    int retrans;               /* 3 */
    uint32_t retrans_maxseq;   /* 32768 */
    uint32_t incoming_maxseq;  /* 4096 */
    int udp_out, udp_in;       /* 4, 1 */
    int syn_tries;             /* 2 */
    int rst_ttl_delta;         /* 2 */
    double p0, p1, alpha, beta; /* 0.1, 0.6, 0.05, 0.05 */
    size_t max_keys;           /* 4096 */
    unsigned key_idle_s;       /* keys idle this long are forgotten (3600) */
} xdet_config;

void xdet_config_default(xdet_config *c);

/* A flow's outcome */
typedef struct {
    const ct_flow *f;
    int ok;         /* 1 success, 0 failure */
    int cls;        /* XC_* of a failure */
    const char *host; /* NULL: not known */
    const char *why;  /* one line */
} xdet_flow_ev;

/* A key's state changed */
typedef struct {
    const char *key;
    int level;      /* XK_* */
    int impaired;   /* 1 impaired, 0 healthy again */
    int cls;        /* XC_* (impaired) */
    unsigned flows, fails;
    int class_change; /* only the class changed */
} xdet_key_ev;

typedef struct {
    void (*flow)(void *ud, const xdet_flow_ev *ev);
    void (*key)(void *ud, const xdet_key_ev *ev);
    void *ud;
} xdet_sink;

typedef struct xdet xdet;

xdet *xdet_new(const xdet_config *c, const ct_config *ct, const xdet_sink *s);
void xdet_free(xdet *d);

/* One packet as observed (either direction; the conntrack tells which) */
void xdet_packet(xdet *d, const gpkt *p, uint64_t now_ms);

typedef struct {
    uint64_t packets, flows_ok, flows_failed;
    size_t flows, keys, impaired;
} xdet_stats;
void xdet_get_stats(const xdet *d, xdet_stats *s);

/* The keys as JSON: [{"key":..,"level":..,"impaired":..,"class":..,
 * "flows":..,"fails":..,"classes":{..}}], impaired ones only when
 * impaired_only */
void xdet_keys_json(const xdet *d, jw *w, int impaired_only);

#endif
