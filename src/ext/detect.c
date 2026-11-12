/*
 * The detector of --ext-auto (detect.h).
 */
#include "detect.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hostlist.h"
#include "ipcache.h"
#include "l7.h"
#include "log.h"
#include "util.h"

#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif

static const char *const class_names[XC_N] = {
    "none",          "RETRANS",       "RST_IN",   "RST_INJECT", "REDIRECT",  "UDP_NOANSWER",
    "BLACKHOLE_SYN", "ICMP_PROHIBIT", "FREEZE_N", "THROTTLE",   "DNS_POISON"};
static const char *const level_names[XK_LEVELS] = {"port", "net", "ip", "host"};

const char *xdet_class_name(int c) { return c >= 0 && c < XC_N ? class_names[c] : "?"; }
const char *xdet_level_name(int l) { return l >= 0 && l < XK_LEVELS ? level_names[l] : "?"; }

void xdet_config_default(xdet_config *c)
{
    memset(c, 0, sizeof(*c));
    c->retrans = 3;
    c->retrans_maxseq = 32768;
    c->incoming_maxseq = 4096;
    c->udp_out = 4;
    c->udp_in = 1;
    c->syn_tries = 2;
    c->rst_ttl_delta = 2;
    c->p0 = 0.1;
    c->p1 = 0.6;
    c->alpha = c->beta = 0.05;
    c->max_keys = 4096;
    c->key_idle_s = 3600;
    c->freeze_min = 8192;
    c->freeze_max = 65536;
    c->freeze_silence_ms = 3000;
    c->freeze_iqr = 4096;
    c->freeze_flows = 3;
    c->throttle_rho = 0.25;
    c->throttle_cv = 0.3;
    c->throttle_windows = 5;
    c->throttle_min_bytes = 65536;
    c->link_share = 0.3;
    c->link_min_keys = 5;
    c->watch_max = 512;
    c->watch_s = 120;
}

/* ---- keys ---------------------------------------------------------------------- */

#define KEY_BUCKETS 1024
#define FREEZE_KEEP 8            /* B of the last freezes per key */
#define FREEZE_WINDOW 600000u    /* ms they count */
#define LINK_WINDOW 30000u       /* ms */
#define RATES 16                 /* rate windows kept per flow */

typedef struct xkey xkey;
struct xkey {
    xkey *next;
    char *name;
    int level;
    double llr;
    int impaired, cls;
    unsigned flows, fails;
    unsigned classes[XC_N];
    uint64_t t_last, t_fail;
    /* FREEZE_N: the B of the last freezes (a ring) and when */
    uint32_t fz_b[FREEZE_KEEP];
    uint64_t fz_t[FREEZE_KEEP];
    unsigned nfz;
    int pin;              /* XC_FREEZE once the freezes decided the key */
    /* the stricter success while impaired by FREEZE_N or THROTTLE */
    uint64_t strict_b;    /* more than 2 * this many bytes */
    double strict_rate;   /* a median rate over 3 * this */
};

typedef struct vwatch vwatch;

struct xdet {
    xdet_config c;
    xdet_sink s;
    ctrack *ct;
    xkey *b[KEY_BUCKETS];
    size_t nkeys, nimpaired;
    double up, down, a, bnd; /* llr steps and bounds */
    uint64_t packets, ok, failed, last_purge;
    /* the flows whose counters are polled */
    ct_flow **watch;
    size_t nwatch;
    double cap;         /* C, bytes/s */
    uint64_t t_cap;     /* when C was last raised */
    int link_bad;
    uint64_t t_link;
};

static uint32_t hash_str(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s)
        h = (h ^ (uint8_t)*s++) * 16777619u;
    return h;
}

static xkey *key_get(xdet *d, const char *name, int level, uint64_t now, int create)
{
    uint32_t h = hash_str(name) % KEY_BUCKETS;
    xkey *k;
    for (k = d->b[h]; k; k = k->next)
        if (k->level == level && !strcmp(k->name, name))
            return k;
    if (!create || d->nkeys >= d->c.max_keys)
        return NULL;
    k = xcalloc(1, sizeof(*k));
    k->name = xstrdup(name);
    k->level = level;
    k->t_last = now;
    k->next = d->b[h];
    d->b[h] = k;
    d->nkeys++;
    return k;
}

static void key_free(xkey *k)
{
    free(k->name);
    free(k);
}

/* keys idle too long (an impaired one too: nothing tells of it any more) */
static void keys_purge(xdet *d, uint64_t now)
{
    uint64_t idle = (uint64_t)d->c.key_idle_s * 1000;
    /* every 10 s, every second while the table is full */
    if (now - d->last_purge < (d->nkeys < d->c.max_keys ? 10000u : 1000u))
        return;
    d->last_purge = now;
    for (int i = 0; i < KEY_BUCKETS; i++) {
        xkey **pp = &d->b[i];
        while (*pp) {
            xkey *k = *pp;
            if (now - k->t_last >= idle) {
                *pp = k->next;
                d->nkeys--;
                if (k->impaired)
                    d->nimpaired--;
                key_free(k);
            } else {
                pp = &k->next;
            }
        }
    }
}

static int top_class(const xkey *k)
{
    int best = XC_NONE;
    for (int c = 1; c < XC_N; c++)
        if (k->classes[c] > (best ? k->classes[best] : 0))
            best = c;
    return best;
}

static void clamp(xdet *d, xkey *k)
{
    if (k->llr >= d->a) {
        k->llr = d->a;
        k->impaired = 1;
    } else if (k->llr <= d->bnd) {
        k->llr = d->bnd;
        k->impaired = 0;
    }
}

/* after a change of k: its class, the counters and the event */
static void key_settle(xdet *d, xkey *k, int was, int before)
{
    xdet_key_ev ev;
    if (k->impaired)
        k->cls = k->pin ? k->pin : top_class(k);
    else
        k->strict_b = 0, k->strict_rate = 0, k->pin = 0;
    if (k->impaired == was && (!k->impaired || k->cls == before))
        return;
    if (k->impaired != was)
        d->nimpaired += k->impaired ? 1 : (size_t)-1;
    memset(&ev, 0, sizeof(ev));
    ev.key = k->name;
    ev.level = k->level;
    ev.impaired = k->impaired;
    ev.cls = k->impaired ? k->cls : XC_NONE;
    ev.flows = k->flows;
    ev.fails = k->fails;
    ev.class_change = k->impaired == was;
    if (d->s.key)
        d->s.key(d->s.ud, &ev);
}

static void count_class(xkey *k, int cls)
{
    if (cls > 0 && cls < XC_N && ++k->classes[cls] > 1000)
        for (int c = 0; c < XC_N; c++)
            k->classes[c] /= 2;
}

static void key_outcome(xdet *d, xkey *k, int ok, int cls, uint64_t now)
{
    int was = k->impaired, before = k->cls;
    k->t_last = now;
    k->flows++;
    if (!ok) {
        k->fails++;
        k->t_fail = now;
        count_class(k, cls);
    }
    k->llr += ok ? d->down : d->up;
    clamp(d, k);
    key_settle(d, k, was, before);
}

/* a success of k taken back (the flow turned out frozen, throttled or
 * poisoned) */
static void key_undo_ok(xdet *d, xkey *k)
{
    int was = k->impaired, before = k->cls;
    if (k->flows)
        k->flows--;
    k->llr -= d->down;
    clamp(d, k);
    key_settle(d, k, was, before);
}

/* FREEZE_N of a flow at b bytes: the key takes the class when the last
 * freeze_flows freezes are alike */
static void key_freeze(xdet *d, xkey *k, uint64_t b, uint64_t now)
{
    int was = k->impaired, before = k->cls;
    uint32_t v[FREEZE_KEEP];
    unsigned n = 0;
    k->t_last = k->t_fail = now;
    k->flows++;
    k->fails++;
    count_class(k, XC_FREEZE);
    k->fz_b[k->nfz % FREEZE_KEEP] = (uint32_t)b;
    k->fz_t[k->nfz % FREEZE_KEEP] = now;
    k->nfz++;
    for (unsigned i = 0; i < FREEZE_KEEP && i < k->nfz; i++)
        if (now - k->fz_t[i] <= FREEZE_WINDOW)
            v[n++] = k->fz_b[i];
    if (n >= (unsigned)d->c.freeze_flows) {
        /* sorted, then the interquartile range */
        for (unsigned i = 1; i < n; i++)
            for (unsigned j = i; j > 0 && v[j - 1] > v[j]; j--) {
                uint32_t t = v[j];
                v[j] = v[j - 1], v[j - 1] = t;
            }
        if (v[(3 * n) / 4 < n ? (3 * n) / 4 : n - 1] - v[n / 4] < d->c.freeze_iqr) {
            k->llr = d->a;
            k->impaired = 1;
            k->pin = XC_FREEZE;
            k->strict_b = v[n / 2];
            key_settle(d, k, was, before);
            return;
        }
    }
    key_settle(d, k, was, before);
}

/* the flow's keys, from the most general */
static void flow_keys(const ct_flow *f, const char *host, char names[XK_LEVELS][300])
{
    char a[64];
    uint8_t net[16];
    int af = f->ver == 6 ? AF_INET6 : AF_INET;
    snprintf(names[XK_PORT], 300, "%s/%u", f->proto == 6 ? "tcp" : f->proto == 17 ? "udp" : "ip", f->sport);
    memcpy(net, f->srv, 16);
    if (f->ver == 6)
        memset(net + 6, 0, 10);
    else
        net[3] = 0;
    inet_ntop(af, net, a, sizeof(a));
    snprintf(names[XK_NET], 300, "%s/%d", a, f->ver == 6 ? 48 : 24);
    inet_ntop(af, f->srv, a, sizeof(a));
    snprintf(names[XK_IP], 300, "%s", a);
    snprintf(names[XK_HOST], 300, "%s", host ? host : "");
}

/* ---- flows --------------------------------------------------------------------- */

/* the detector's part of ct_flow.xstate */
typedef struct {
    uint8_t decided, ok;   /* the outcome; ok: a success */
    uint8_t okmask;        /* keys (1 << level) that took the success */
    uint8_t skipmask;      /* keys that did not: their stricter success is due */
    uint8_t retrans, syns, synack_ttl, synack_seen, host_tried;
    uint8_t redecided;     /* the success was taken back or turned */
    uint8_t dns_seen, dns_ttl;
    uint8_t dns_stub;      /* the failure is a stub address: the host's only */
    uint16_t dns_id;
} fstate;

typedef char fstate_fits[sizeof(fstate) <= CT_XSTATE ? 1 : -1];

static fstate *fs_of(ct_flow *f) { return (fstate *)(void *)f->xstate; }

/* The volume watch of a flow (X9b). The detector's own conntrack has no
 * x-actions, so their pointer ct_flow.xa holds it. */
struct vwatch {
    size_t idx; /* in d->watch */
    uint64_t t_start, t_change, t_sample;
    uint32_t rtt;
    uint64_t rbytes;
    float rate[RATES];       /* the last windows' rates (a ring) */
    int nrate, data_windows; /* windows with data so far (the first is left out) */
    uint8_t freeze_done, throttle_done, done;
    uint8_t self_closed;     /* self_count: a FIN or RST seen */
    uint64_t self_rb;        /* self_count: the server's bytes seen */
};

static vwatch *vw_of(ct_flow *f) { return (vwatch *)f->xa; }

static void watch_drop(xdet *d, ct_flow *f)
{
    vwatch *w = vw_of(f);
    if (!w)
        return;
    d->watch[w->idx] = d->watch[--d->nwatch];
    vw_of(d->watch[w->idx])->idx = w->idx;
    free(w);
    f->xa = NULL;
}

static void flow_clear(ct_flow *f, void *ud)
{
    watch_drop(ud, f);
    free(f->chost);
    f->chost = NULL;
}

static void watch_add(xdet *d, ct_flow *f, uint64_t now)
{
    vwatch *w;
    if (f->xa || d->nwatch >= d->c.watch_max)
        return;
    w = xcalloc(1, sizeof(*w));
    w->idx = d->nwatch;
    w->t_start = w->t_change = w->t_sample = now;
    w->rtt = (uint32_t)(now - f->t_start);
    d->watch[d->nwatch++] = f;
    f->xa = w;
    LOGD("detect", "watching the counters of the flow from port %u to port %u", f->cport, f->sport);
}

xdet *xdet_new(const xdet_config *c, const ct_config *ctc, const xdet_sink *s)
{
    xdet *d = xcalloc(1, sizeof(*d));
    ct_config cc = *ctc;
    d->c = *c;
    if (s)
        d->s = *s;
    cc.clear = flow_clear;
    cc.clear_ud = d;
    d->watch = xcalloc(d->c.watch_max ? d->c.watch_max : 1, sizeof(*d->watch));
    d->ct = ctrack_new(&cc);
    d->up = log(d->c.p1 / d->c.p0);
    d->down = log((1 - d->c.p1) / (1 - d->c.p0));
    d->a = log((1 - d->c.beta) / d->c.alpha);
    d->bnd = log(d->c.beta / (1 - d->c.alpha));
    return d;
}

void xdet_free(xdet *d)
{
    if (!d)
        return;
    ctrack_free(d->ct); /* the watches go with their flows */
    free(d->watch);
    for (int i = 0; i < KEY_BUCKETS; i++)
        while (d->b[i]) {
            xkey *k = d->b[i];
            d->b[i] = k->next;
            key_free(k);
        }
    free(d);
}

static const char *flow_host(ct_flow *f)
{
    char h[256];
    int ip;
    if (f->chost)
        return f->chost;
    if (xipc_get_host(f->ver, f->srv, h, sizeof(h), &ip) && !ip)
        return f->chost = xstrdup(h);
    return NULL;
}

static void flow_event(xdet *d, ct_flow *f, int ok, int cls, const char *why)
{
    xdet_flow_ev ev;
    memset(&ev, 0, sizeof(ev));
    ev.f = f;
    ev.ok = ok;
    ev.cls = ok ? XC_NONE : cls;
    ev.host = flow_host(f);
    ev.why = why;
    if (d->s.flow)
        d->s.flow(d->s.ud, &ev);
}

/* the stricter success of a key impaired by FREEZE_N or THROTTLE */
static int strict(const xkey *k) { return k->impaired && (k->strict_b || k->strict_rate > 0); }

static void decide(xdet *d, ct_flow *f, int ok, int cls, const char *why, uint64_t now)
{
    fstate *fs = fs_of(f);
    char names[XK_LEVELS][300];
    if (fs->decided)
        return;
    fs->decided = 1;
    fs->ok = (uint8_t)ok;
    if (ok)
        d->ok++;
    else
        d->failed++;
    flow_event(d, f, ok, cls, why);
    flow_keys(f, flow_host(f), names);
    for (int l = 0; l < XK_LEVELS; l++) {
        xkey *k;
        if (!names[l][0] || !(k = key_get(d, names[l], l, now, 1)))
            continue;
        if (!ok && fs->dns_stub && l != XK_HOST)
            continue;
        if (ok && strict(k) && f->proto == 6) {
            fs->skipmask |= (uint8_t)(1 << l); /* the volume watch decides */
            k->t_last = now;
            continue;
        }
        key_outcome(d, k, ok, cls, now);
        if (ok)
            fs->okmask |= (uint8_t)(1 << l);
    }
}

/* A success proven wrong: FREEZE_N takes it back and tells the key of the
 * freeze, THROTTLE and DNS_POISON turn it into that failure. A flow
 * without an outcome yet gets the failure (or, for a freeze, only the
 * freeze). */
static void redecide(xdet *d, ct_flow *f, int cls, uint64_t b, const char *why, uint64_t now)
{
    fstate *fs = fs_of(f);
    char names[XK_LEVELS][300];
    if (fs->redecided || (fs->decided && !fs->ok))
        return;
    fs->redecided = 1;
    if (fs->decided)
        d->ok--;
    d->failed++;
    fs->decided = 1;
    fs->ok = 0;
    flow_event(d, f, 0, cls, why);
    flow_keys(f, flow_host(f), names);
    for (int l = 0; l < XK_LEVELS; l++) {
        xkey *k;
        if (!names[l][0] || (fs->dns_stub && l != XK_HOST) || !(k = key_get(d, names[l], l, now, 1)))
            continue;
        if (fs->okmask & (1 << l))
            key_undo_ok(d, k);
        if (cls == XC_FREEZE)
            key_freeze(d, k, b, now);
        else
            key_outcome(d, k, 0, cls, now);
    }
    fs->okmask = fs->skipmask = 0;
}

/* the stricter success came: the keys that waited for it take it */
static void strict_ok(xdet *d, ct_flow *f, uint64_t rbytes, double rate, uint64_t now)
{
    fstate *fs = fs_of(f);
    char names[XK_LEVELS][300];
    if (!fs->skipmask)
        return;
    flow_keys(f, flow_host(f), names);
    for (int l = 0; l < XK_LEVELS; l++) {
        xkey *k;
        if (!(fs->skipmask & (1 << l)) || !(k = key_get(d, names[l], l, now, 0)))
            continue;
        if (k->strict_b ? rbytes > 2 * k->strict_b : rate > 3 * k->strict_rate) {
            key_outcome(d, k, 1, XC_NONE, now);
            fs->skipmask &= (uint8_t)~(1 << l);
            fs->okmask |= (uint8_t)(1 << l);
        }
    }
}

static int seq_within(uint32_t x, uint32_t a, uint32_t b) { return x - a <= b - a; }

/* the client's first data: its host name (TLS SNI or HTTP Host:; other
 * flows get theirs from the address cache, which the detector only reads:
 * the profiles' host names stay what the engine itself learnt) */
static void set_host(ct_flow *f, const char *h)
{
    char n[256];
    int ip = xhost_norm(h, n, sizeof(n));
    if (!n[0])
        return;
    free(f->chost);
    f->chost = xstrdup(n);
    f->chost_ip = (uint8_t)ip;
}

static void learn_host(ct_flow *f, const gpkt *p)
{
    fstate *fs = fs_of(f);
    char h[256];
    if (fs->host_tried || !p->payload_len || f->proto != 6)
        return;
    fs->host_tried = 1;
    if (l7_tls_host(p->payload, p->payload_len, h, sizeof(h), 1) ||
        l7_http_host(p->payload, p->payload_len, h, sizeof(h)))
        set_host(f, h);
}

static void tcp_packet(xdet *d, ct_flow *f, int reverse, const gpkt *p, uint64_t now)
{
    fstate *fs = fs_of(f);
    const xdet_config *c = &d->c;
    uint16_t fl = p->tcpflags;
    if (!reverse) {
        if ((fl & 0x12) == 0x02) { /* SYN */
            if (f->state == CT_SYN && !fs->synack_seen && ++fs->syns >= c->syn_tries)
                decide(d, f, 0, XC_BLACKHOLE_SYN, "SYN sent again without a SYN,ACK", now);
            return;
        }
        if (!p->payload_len || f->state == CT_SYN)
            return;
        learn_host(f, p);
        if (!seq_within(f->client.seq_last, f->client.seq0, f->client.seq0 + c->retrans_maxseq)) {
            decide(d, f, 1, XC_NONE, "the client is past retrans_maxseq", now);
            return;
        }
        if (!ct_is_retrans(&f->client))
            return;
        if (++fs->retrans >= c->retrans)
            decide(d, f, 0, XC_RETRANS, "the client sent its data again", now);
        return;
    }
    if ((fl & 0x12) == 0x12) { /* SYN,ACK */
        if (!fs->synack_seen)
            watch_add(d, f, now);
        fs->synack_seen = 1;
        fs->synack_ttl = p->ipver == 6 ? p->hlim : p->ttl;
        return;
    }
    if (!f->server.seq0 && !fs->synack_seen)
        return;
    if (!seq_within(f->server.seq_last, f->server.seq0 + 1, f->server.seq0 + c->incoming_maxseq)) {
        if (f->server.seq_last != f->server.seq0)
            decide(d, f, 1, XC_NONE, "the server is past incoming_maxseq", now);
        return;
    }
    if (fl & 0x04) {
        /* zapret2 takes any RST in incoming_maxseq; a server that sent its
         * answer and then aborts (a short exchange ended with a RST) is no
         * block, so a RST after the server's data counts only with a TTL
         * that is not the server's */
        int ttl = p->ipver == 6 ? p->hlim : p->ttl, diff = ttl - fs->synack_ttl;
        if (fs->synack_seen && (diff >= c->rst_ttl_delta || -diff >= c->rst_ttl_delta))
            decide(d, f, 0, XC_RST_INJECT, "a RST with another TTL than the SYN,ACK's", now);
        else if (!f->server.pdcounter)
            decide(d, f, 0, XC_RST_IN, "a RST from the server before its data", now);
        return;
    }
    if (p->payload_len && l7_is_http_reply(p->payload, p->payload_len)) {
        const char *host = flow_host(f);
        if (host && l7_http_dpi_redirect(p->payload, p->payload_len, host))
            decide(d, f, 0, XC_REDIRECT, "an HTTP redirect to another domain", now);
    }
}

/* ---- DNS ----------------------------------------------------------------------- */

/* a DNS name at off (compression followed for the question only when
 * out is given): the offset after it, or 0 */
static size_t dns_name(const uint8_t *m, size_t n, size_t off, char *out, size_t cap)
{
    size_t o = 0;
    for (int labels = 0; labels < 128 && off < n; labels++) {
        uint8_t l = m[off];
        if (!l) {
            if (out)
                out[o ? o - 1 : 0] = 0;
            return off + 1;
        }
        if ((l & 0xc0) == 0xc0) {
            if (out)
                return 0; /* the question is not compressed */
            return off + 2 <= n ? off + 2 : 0;
        }
        if (l & 0xc0 || off + 1 + l > n)
            return 0;
        if (out) {
            if (o + l + 1 >= cap)
                return 0;
            for (unsigned i = 0; i < l; i++) {
                char ch = (char)m[off + 1 + i];
                out[o++] = ch >= 'A' && ch <= 'Z' ? (char)(ch - 'A' + 'a') : ch;
            }
            out[o++] = '.';
        }
        off += 1u + l;
    }
    return 0;
}

static int dns_stub(int type, const uint8_t *a)
{
    static const uint8_t z[16];
    if (type == 1)
        return !memcmp(a, z, 4) || a[0] == 127;
    return !memcmp(a, z, 16) || (!memcmp(a, z, 15) && a[15] == 1);
}

/* An answer: its id and question name; *stub when an A/AAAA answer is a
 * stub address. Returns 0, or -1 when it is not one. */
static int dns_parse(const uint8_t *m, size_t n, uint16_t *id, char *name, size_t cap, int *stub)
{
    size_t off;
    unsigned an;
    *stub = 0;
    if (n < 12 || !(m[2] & 0x80) || ((m[4] << 8) | m[5]) != 1)
        return -1;
    *id = (uint16_t)(m[0] << 8 | m[1]);
    an = (unsigned)(m[6] << 8 | m[7]);
    off = dns_name(m, n, 12, name, cap);
    if (!off || off + 4 > n)
        return -1;
    off += 4;
    for (unsigned i = 0; i < an && i < 64; i++) {
        unsigned type, rdlen;
        off = dns_name(m, n, off, NULL, 0);
        if (!off || off + 10 > n)
            break;
        type = (unsigned)(m[off] << 8 | m[off + 1]);
        rdlen = (unsigned)(m[off + 8] << 8 | m[off + 9]);
        off += 10;
        if (off + rdlen > n)
            break;
        if (((type == 1 && rdlen == 4) || (type == 28 && rdlen == 16)) && dns_stub((int)type, m + off))
            *stub = 1;
        off += rdlen;
    }
    return 0;
}

static void dns_answer(xdet *d, ct_flow *f, const gpkt *p, uint64_t now)
{
    fstate *fs = fs_of(f);
    char name[256];
    uint16_t id;
    int stub;
    uint8_t ttl = p->ipver == 6 ? p->hlim : p->ttl;
    if (dns_parse(p->payload, p->payload_len, &id, name, sizeof(name), &stub) < 0)
        return;
    if (name[0] && !f->chost)
        set_host(f, name);
    if (stub) {
        /* an ad-blocking resolver answers so too: the host's failure, not
         * the resolver's (an injected answer is, below) */
        fs->dns_stub = 1;
        if (fs->decided)
            redecide(d, f, XC_DNS_POISON, 0, "a DNS answer with a stub address", now);
        else
            decide(d, f, 0, XC_DNS_POISON, "a DNS answer with a stub address", now);
        return;
    }
    if (!fs->dns_seen) {
        fs->dns_seen = 1;
        fs->dns_id = id;
        fs->dns_ttl = ttl;
        decide(d, f, 1, XC_NONE, "a DNS answer", now);
    } else if (id == fs->dns_id && ttl != fs->dns_ttl) {
        redecide(d, f, XC_DNS_POISON, 0, "two DNS answers to one query, the first with another TTL", now);
    }
}

static void udp_packet(xdet *d, ct_flow *f, int reverse, const gpkt *p, uint64_t now)
{
    if (f->sport == 53) {
        if (reverse && p->payload_len)
            dns_answer(d, f, p, now);
        else if (!fs_of(f)->decided && f->client.pcounter >= (uint64_t)d->c.udp_out)
            decide(d, f, 0, XC_UDP_NOANSWER, "DNS queries without an answer", now);
        return;
    }
    if (fs_of(f)->decided)
        return;
    if (f->server.pcounter > (uint64_t)d->c.udp_in)
        decide(d, f, 1, XC_NONE, "the server answers", now);
    else if (f->client.pcounter >= (uint64_t)d->c.udp_out)
        decide(d, f, 0, XC_UDP_NOANSWER, "datagrams without an answer", now);
}

/* an ICMP error about the flow */
static void icmp_packet(xdet *d, ct_flow *f, const gpkt *p, uint64_t now)
{
    uint8_t t, code;
    if (p->payload_len < 2)
        return;
    t = p->payload[0];
    code = p->payload[1];
    if ((p->l4proto == 1 && t == 3 && (code == 9 || code == 10 || code == 13)) ||
        (p->l4proto == 58 && t == 1 && code == 1))
        decide(d, f, 0, XC_ICMP_PROHIBIT, "ICMP administratively prohibited", now);
}

static int unicast(const ct_flow *f)
{
    const uint8_t *a = f->srv;
    if (f->ver == 6)
        return a[0] != 0xff && !(a[0] == 0xfe && (a[1] & 0xc0) == 0x80);
    return a[0] < 224 && !(a[0] == 169 && a[1] == 254) && !(a[0] == 255);
}

void xdet_packet(xdet *d, const gpkt *p, uint64_t now)
{
    int reverse = 0;
    ct_flow *f;
    fstate *fs;
    d->packets++;
    keys_purge(d, now);
    f = ctrack_feed(d->ct, p, now, &reverse);
    if (!f)
        return;
    fs = fs_of(f);
    if (d->c.self_count && f->xa) {
        /* what the conntrack's counters would say: IP bytes from the
         * server, and whether the flow still lives */
        vwatch *w = vw_of(f);
        if (reverse)
            w->self_rb += p->ipver == 6 ? (uint64_t)p->plen + 40 : p->iplen;
        if (p->l4 == LAYER_TCP && (p->tcpflags & 0x05))
            w->self_closed = 1;
    }
    if (fs->decided && !(f->proto == 17 && f->sport == 53 && fs->ok && !fs->redecided))
        return; /* (a DNS answer that came first may still prove poisoned) */
    if (!unicast(f)) {
        /* multicast and broadcast get no answer on their flow (mDNS,
         * SSDP), link-local is the LAN: no outcome */
        fs->decided = 1;
        fs->redecided = 1;
        return;
    }
    if (p->l4 == LAYER_TCP && f->proto == 6)
        tcp_packet(d, f, reverse, p, now);
    else if (p->l4 == LAYER_UDP && f->proto == 17)
        udp_packet(d, f, reverse, p, now);
    else if (p->l4 == LAYER_NONE && (p->l4proto == 1 || p->l4proto == 58) && !fs->decided)
        icmp_packet(d, f, p, now);
}

void xdet_packet_dir(xdet *d, const gpkt *p, uint64_t now, int out)
{
    /* an ICMP error the PC sends is about a flow of another's; one that
     * comes in finds its flow by the packet inside */
    if ((p->l4 == LAYER_NONE && out) ||
        (p->l4 != LAYER_NONE && !ctrack_find(d->ct, p, NULL) &&
         (!out || (p->l4 == LAYER_TCP && (p->tcpflags & 0x12) == 0x12)))) {
        d->packets++;
        return;
    }
    xdet_packet(d, p, now);
}

/* ---- volume -------------------------------------------------------------------- */

static int cmp_float(const void *a, const void *b)
{
    float x = *(const float *)a, y = *(const float *)b;
    return x < y ? -1 : x > y;
}

/* the median, coefficient of variation and maximum of a flow's last n
 * rate windows; 0 when it has fewer */
static int rates_of(const vwatch *w, int n, double *med, double *cv, double *max)
{
    float v[RATES];
    double mean = 0, var = 0;
    if (n < 1 || n > RATES || w->nrate < n)
        return 0;
    for (int i = 0; i < n; i++)
        v[i] = w->rate[(w->nrate - 1 - i) % RATES];
    qsort(v, (size_t)n, sizeof(v[0]), cmp_float);
    *med = n % 2 ? v[n / 2] : (v[n / 2 - 1] + v[n / 2]) / 2;
    for (int i = 0; i < n; i++)
        mean += v[i];
    mean /= n;
    for (int i = 0; i < n; i++)
        var += (v[i] - mean) * (v[i] - mean);
    var /= n;
    *cv = mean > 0 ? sqrt(var) / mean : 0;
    *max = v[n - 1];
    return 1;
}

static int is_plateau(const xdet *d, double med, double cv, double max)
{
    return med > 0 && med < d->c.throttle_rho * d->cap && cv < d->c.throttle_cv && max <= 2 * med;
}

static int same_net(const ct_flow *a, const ct_flow *b)
{
    if (a->ver != b->ver)
        return 0;
    return a->ver == 6 ? !memcmp(a->srv, b->srv, 6) : !memcmp(a->srv, b->srv, 3);
}

/* a flow to another network, live now, on a plateau like med: the own
 * link (or the PC) is the bottleneck, not a censor of this flow's keys */
static const ct_flow *parallel_plateau(const xdet *d, const ct_flow *f, double med, uint64_t now)
{
    int n = d->c.throttle_windows < RATES ? d->c.throttle_windows : RATES;
    for (size_t i = 0; i < d->nwatch; i++) {
        const ct_flow *o = d->watch[i];
        const vwatch *w = vw_of((ct_flow *)o);
        double m, cv, mx;
        /* a flow that began a little later has fewer windows: two do */
        if (o == f || same_net(o, f) || w->done || now - w->t_change > 2000 || w->nrate < 2 ||
            w->rbytes < d->c.throttle_min_bytes / 4 || !rates_of(w, w->nrate < n ? w->nrate : n, &m, &cv, &mx))
            continue;
        if (is_plateau(d, m, cv, mx) && m >= med / 2 && m <= med * 2)
            return o;
    }
    return NULL;
}

/* THROTTLE: a flat plateau far under C over the last throttle_windows
 * windows (a burst or a stall earlier in the flow ages out) */
static void check_throttle(xdet *d, ct_flow *f, vwatch *w, uint64_t now)
{
    double med, cv, mx;
    const ct_flow *o;
    int n = d->c.throttle_windows < RATES ? d->c.throttle_windows : RATES;
    if (w->throttle_done || w->rbytes < d->c.throttle_min_bytes || d->cap <= 0 || !rates_of(w, n, &med, &cv, &mx))
        return;
    LOGD("detect", "rates of a flow: %d windows, median %.0f B/s, cv %.2f, max %.0f, C %.0f", n, med, cv, mx,
         d->cap);
    if (!is_plateau(d, med, cv, mx))
        return;
    if ((o = parallel_plateau(d, f, med, now)) != NULL) {
        LOGD("detect", "the flow from port %u plateaus like the one from port %u to another network: the link",
             f->cport, o->cport);
        return;
    }
    w->throttle_done = 1;
    {
        char why[128];
        char names[XK_LEVELS][300];
        snprintf(why, sizeof(why), "a plateau of %.0f B/s, capacity %.0f B/s", med, d->cap);
        redecide(d, f, XC_THROTTLE, 0, why, now);
        /* the keys impaired by it want 3 times the plateau from now on */
        flow_keys(f, flow_host(f), names);
        for (int l = 0; l < XK_LEVELS; l++) {
            xkey *k = names[l][0] ? key_get(d, names[l], l, now, 0) : NULL;
            if (k && k->impaired && k->cls == XC_THROTTLE && !k->strict_b)
                k->strict_rate = med;
        }
    }
}

static void counters_of(xdet *d, ct_flow *f, const xdet_ctr *c, uint64_t now)
{
    vwatch *w = vw_of(f);
    if (!w || w->done)
        return;
    if (c->found && c->rbytes != w->rbytes) {
        uint64_t dt = now > w->t_sample ? now - w->t_sample : 1;
        double r = (double)(c->rbytes - w->rbytes) * 1000.0 / (double)dt;
        if (c->rbytes > w->rbytes && w->data_windows++ > 0 && dt >= 500) {
            /* the first window with data holds the handshake and a burst;
             * a short one (an answer late, the next early) says little */
            w->rate[w->nrate++ % RATES] = (float)r;
            if (r > d->cap || now - d->t_cap > FREEZE_WINDOW) { /* C forgets after 10 minutes */
                if (r > 2 * d->cap)
                    LOGD("detect", "capacity C: %.0f B/s", r);
                d->cap = r;
                d->t_cap = now;
            }
        }
        w->rbytes = c->rbytes;
        w->t_change = now;
        check_throttle(d, f, w, now);
        strict_ok(d, f, w->rbytes, w->nrate ? (double)w->rate[(w->nrate - 1) % RATES] : 0, now);
    } else if (c->found && c->open && !w->freeze_done && w->rbytes >= d->c.freeze_min &&
               w->rbytes <= d->c.freeze_max) {
        uint64_t silence = 4ull * w->rtt;
        if (silence < d->c.freeze_silence_ms)
            silence = d->c.freeze_silence_ms;
        if (now - w->t_change >= silence) {
            char why[96];
            w->freeze_done = 1;
            snprintf(why, sizeof(why), "the server's data stopped at %llu bytes", (unsigned long long)w->rbytes);
            redecide(d, f, XC_FREEZE, w->rbytes, why, now);
        }
    }
    w->t_sample = now;
    if (!c->found || !c->open) {
        if (w->nrate)
            check_throttle(d, f, w, now);
        if (!w->done)
            LOGD("detect", "the flow from port %u ended (%s) after %llu bytes, %d rate windows", f->cport,
                 c->found ? "closed" : "gone", (unsigned long long)w->rbytes, w->nrate);
        w->done = 1; /* closed: nothing more to see */
    }
}

void xdet_counters(xdet *d, const xdet_ctr *c, uint64_t now)
{
    if (d->c.self_count)
        return;
    for (size_t i = 0; i < d->nwatch; i++) {
        ct_flow *x = d->watch[i];
        if (x->ver == c->t.ver && x->proto == c->t.proto && x->cport == c->t.cport && x->sport == c->t.sport &&
            !memcmp(x->cli, c->t.cli, x->ver == 6 ? 16 : 4) && !memcmp(x->srv, c->t.srv, x->ver == 6 ? 16 : 4)) {
            counters_of(d, x, c, now);
            return;
        }
    }
}

/* LINK_DEGRADED over the address keys */
static void check_link(xdet *d, uint64_t now)
{
    unsigned active = 0, bad = 0;
    int deg;
    for (int i = 0; i < KEY_BUCKETS; i++)
        for (const xkey *k = d->b[i]; k; k = k->next)
            if (k->level == XK_IP && now - k->t_last <= LINK_WINDOW) {
                active++;
                bad += k->t_fail && now - k->t_fail <= LINK_WINDOW;
            }
    deg = active >= (unsigned)d->c.link_min_keys && bad >= d->c.link_share * active;
    if (deg != d->link_bad) {
        d->link_bad = deg;
        if (d->s.link)
            d->s.link(d->s.ud, deg, bad, active);
    }
}

void xdet_tick(xdet *d, uint64_t now, void (*req)(void *ud, const xdet_tuple *t), void *ud)
{
    size_t i = 0;
    while (i < d->nwatch) {
        ct_flow *f = d->watch[i];
        vwatch *w = vw_of(f);
        if (w->done || now - w->t_start > (uint64_t)d->c.watch_s * 1000) {
            watch_drop(d, f); /* the last one moved here */
            continue;
        }
        if (d->c.self_count) {
            xdet_ctr c;
            memset(&c, 0, sizeof(c));
            c.found = 1;
            c.open = !w->self_closed;
            c.rbytes = w->self_rb;
            counters_of(d, f, &c, now);
        } else if (req) {
            xdet_tuple t;
            memset(&t, 0, sizeof(t));
            t.ver = f->ver;
            t.proto = f->proto;
            memcpy(t.cli, f->cli, 16);
            memcpy(t.srv, f->srv, 16);
            t.cport = f->cport;
            t.sport = f->sport;
            req(ud, &t);
        }
        i++;
    }
    keys_purge(d, now);
    if (now - d->t_link >= 1000) {
        d->t_link = now;
        check_link(d, now);
    }
}

void xdet_get_stats(const xdet *d, xdet_stats *s)
{
    memset(s, 0, sizeof(*s));
    s->packets = d->packets;
    s->flows_ok = d->ok;
    s->flows_failed = d->failed;
    s->flows = ctrack_count(d->ct);
    s->keys = d->nkeys;
    s->impaired = d->nimpaired;
    s->watched = d->nwatch;
    s->capacity = d->cap;
    s->link_degraded = d->link_bad;
}

void xdet_keys_json(const xdet *d, jw *w, int impaired_only)
{
    jw_arr(w);
    for (int l = 0; l < XK_LEVELS; l++)
        for (int i = 0; i < KEY_BUCKETS; i++)
            for (const xkey *k = d->b[i]; k; k = k->next) {
                if (k->level != l || (impaired_only && !k->impaired))
                    continue;
                jw_obj(w);
                jw_kstr(w, "key", k->name);
                jw_kstr(w, "level", level_names[l]);
                jw_kbool(w, "impaired", k->impaired);
                if (k->impaired)
                    jw_kstr(w, "class", class_names[k->cls]);
                jw_kuint(w, "flows", k->flows);
                jw_kuint(w, "fails", k->fails);
                if (k->fails) {
                    jw_key(w, "classes");
                    jw_obj(w);
                    for (int c = 1; c < XC_N; c++)
                        if (k->classes[c])
                            jw_kuint(w, class_names[c], k->classes[c]);
                    jw_obj_end(w);
                }
                jw_obj_end(w);
            }
    jw_arr_end(w);
}
