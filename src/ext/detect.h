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
 * Volume (X9b; the kernel conntrack's counters of the flow, polled about
 * once a second through xdet_tick/xdet_counters while the flow lives, up to
 * watch_s; on Windows the detector counts the packets itself, self_count):
 *
 *   FREEZE_N       the server's bytes stopped at B in [freeze_min,
 *                  freeze_max] (8 KB, 64 KB), the flow still open and
 *                  silent for max(4 RTT, freeze_silence_ms (3 s)). A key
 *                  takes the class when freeze_flows (3) such flows within
 *                  10 minutes have an interquartile range of B under
 *                  freeze_iqr (4 KB): a censor freezes at the same count
 *   THROTTLE       the last throttle_windows (5) one-second windows with
 *                  data (the flow's first one left out): their median rate under
 *                  throttle_rho (0.25) of the capacity C (the fastest window
 *                  of any flow lately), coefficient of variation under
 *                  throttle_cv (0.3), no window over twice the median, and
 *                  throttle_min_bytes (64 KB) in all: a policer's plateau.
 *                  Not while a flow to another network plateaus alike
 *                  (median within half to twice, also under rho C, a
 *                  quarter of throttle_min_bytes): a shared plateau is
 *                  the own link's
 *   DNS_POISON     a DNS answer with a stub address (0.0.0.0, 127/8, ::,
 *                  ::1), or two answers to one query, the first with
 *                  another IP TTL than the second: the first was injected. A stub address counts
 *                  for the host name's key only: ad-blocking resolvers
 *                  answer so too
 *
 * Success (standard_success_detector): the client past retrans_maxseq or
 * the server past incoming_maxseq; UDP: more than udp_in back; DNS: an
 * answer. A key impaired with FREEZE_N or THROTTLE takes a success only
 * from a flow with more than twice the freeze's B, or a median rate over
 * three times the plateau. A flow gets one outcome; a success that a
 * later THROTTLE or DNS_POISON proves wrong becomes that failure, one that
 * FREEZE_N proves wrong is taken back. One that ends undecided gets none.
 *
 * LINK_DEGRADED: when at least link_share (30 %) of the addresses with
 * flows in the last 30 s (at least link_min_keys, 5) had a failure, the
 * fault is likely the own link: the sink is told (and again when it ends).
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
    XC_FREEZE,
    XC_THROTTLE,
    XC_DNS_POISON,
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
    /* volume (X9b) */
    uint32_t freeze_min, freeze_max; /* 8192, 65536 */
    unsigned freeze_silence_ms;      /* 3000 */
    uint32_t freeze_iqr;             /* 4096 */
    int freeze_flows;                /* 3 */
    double throttle_rho, throttle_cv; /* 0.25, 0.3 */
    int throttle_windows;            /* 5 */
    uint64_t throttle_min_bytes;     /* 65536 */
    double link_share;               /* 0.3 */
    int link_min_keys;               /* 5 */
    size_t watch_max;                /* flows whose counters are polled (512) */
    unsigned watch_s;                /* for at most (120) */
    /* the observer sees every packet (WinDivert's SNIFF handle, X9c): the
     * detector counts the server's bytes itself and xdet_tick answers its
     * own requests; no xdet_counters. 0 */
    int self_count;
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
    /* LINK_DEGRADED began (1) or ended (0): bad of active addresses */
    void (*link)(void *ud, int degraded, unsigned bad, unsigned active);
    void *ud;
} xdet_sink;

/* A flow by its client's tuple (the conntrack's original direction) */
typedef struct {
    uint8_t ver, proto;
    uint8_t cli[16], srv[16];
    uint16_t cport, sport;
} xdet_tuple;

/* The kernel conntrack's view of a watched flow */
typedef struct {
    xdet_tuple t;
    int found;          /* 0: gone */
    int open;           /* TCP still established */
    uint64_t rbytes;    /* bytes from the server (IP headers included) */
} xdet_ctr;

typedef struct xdet xdet;

xdet *xdet_new(const xdet_config *c, const ct_config *ct, const xdet_sink *s);
void xdet_free(xdet *d);

/* One packet as observed (either direction; the conntrack tells which) */
void xdet_packet(xdet *d, const gpkt *p, uint64_t now_ms);
/* One packet from an observer that sees every packet (WinDivert): out 1
 * outbound, 0 inbound. Only the PC's own flows count, as with the
 * conntrack's original direction on Linux: an inbound packet starts no
 * flow, nor does an outbound SYN,ACK (a server of the PC answering);
 * ICMP errors count inbound only. */
void xdet_packet_dir(xdet *d, const gpkt *p, uint64_t now_ms, int out);

/* About once a second: the volume checks, LINK_DEGRADED, and req for each
 * watched flow whose counters are wanted (answer with xdet_counters; with
 * self_count the detector's own counts are taken and req is not called) */
void xdet_tick(xdet *d, uint64_t now_ms, void (*req)(void *ud, const xdet_tuple *t), void *ud);
void xdet_counters(xdet *d, const xdet_ctr *c, uint64_t now_ms);

typedef struct {
    uint64_t packets, flows_ok, flows_failed;
    size_t flows, keys, impaired, watched;
    double capacity; /* C, bytes/s (0: not known yet) */
    int link_degraded;
} xdet_stats;
void xdet_get_stats(const xdet *d, xdet_stats *s);

/* The keys as JSON: [{"key":..,"level":..,"impaired":..,"class":..,
 * "flows":..,"fails":..,"classes":{..}}], impaired ones only when
 * impaired_only */
void xdet_keys_json(const xdet *d, jw *w, int impaired_only);

#endif
