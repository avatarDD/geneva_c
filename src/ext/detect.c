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

static const char *const class_names[XC_N] = {"none",         "RETRANS",       "RST_IN",       "RST_INJECT",
                                               "REDIRECT",     "UDP_NOANSWER",  "BLACKHOLE_SYN", "ICMP_PROHIBIT"};
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
}

/* ---- keys ---------------------------------------------------------------------- */

#define KEY_BUCKETS 1024

typedef struct xkey xkey;
struct xkey {
    xkey *next;
    char *name;
    int level;
    double llr;
    int impaired, cls;
    unsigned flows, fails;
    unsigned classes[XC_N];
    uint64_t t_last;
};

struct xdet {
    xdet_config c;
    xdet_sink s;
    ctrack *ct;
    xkey *b[KEY_BUCKETS];
    size_t nkeys, nimpaired;
    double up, down, a, bnd; /* llr steps and bounds */
    uint64_t packets, ok, failed, last_purge;
};

static uint32_t hash_str(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s)
        h = (h ^ (uint8_t)*s++) * 16777619u;
    return h;
}

static xkey *key_get(xdet *d, const char *name, int level, uint64_t now)
{
    uint32_t h = hash_str(name) % KEY_BUCKETS;
    xkey *k;
    for (k = d->b[h]; k; k = k->next)
        if (k->level == level && !strcmp(k->name, name))
            return k;
    if (d->nkeys >= d->c.max_keys)
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

static void key_outcome(xdet *d, xkey *k, int ok, int cls, uint64_t now)
{
    xdet_key_ev ev;
    int was = k->impaired, before = k->cls;
    k->t_last = now;
    k->flows++;
    if (!ok) {
        k->fails++;
        if (cls > 0 && cls < XC_N && ++k->classes[cls] > 1000)
            for (int c = 0; c < XC_N; c++)
                k->classes[c] /= 2;
    }
    k->llr += ok ? d->down : d->up;
    if (k->llr >= d->a) {
        k->llr = d->a;
        k->impaired = 1;
    } else if (k->llr <= d->bnd) {
        k->llr = d->bnd;
        k->impaired = 0;
    }
    if (k->impaired)
        k->cls = top_class(k);
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
    uint8_t decided;
    uint8_t retrans;
    uint8_t syns;
    uint8_t synack_ttl;
    uint8_t synack_seen;
    uint8_t host_tried;
} fstate;

typedef char fstate_fits[sizeof(fstate) <= CT_XSTATE ? 1 : -1];

static fstate *fs_of(ct_flow *f) { return (fstate *)(void *)f->xstate; }

static void flow_clear(ct_flow *f, void *ud)
{
    (void)ud;
    free(f->chost);
    f->chost = NULL;
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
    ctrack_free(d->ct);
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

static void decide(xdet *d, ct_flow *f, int ok, int cls, const char *why, uint64_t now)
{
    fstate *fs = fs_of(f);
    xdet_flow_ev ev;
    char names[XK_LEVELS][300];
    const char *host;
    if (fs->decided)
        return;
    fs->decided = 1;
    host = flow_host(f);
    if (ok)
        d->ok++;
    else
        d->failed++;
    memset(&ev, 0, sizeof(ev));
    ev.f = f;
    ev.ok = ok;
    ev.cls = ok ? XC_NONE : cls;
    ev.host = host;
    ev.why = why;
    if (d->s.flow)
        d->s.flow(d->s.ud, &ev);
    flow_keys(f, host, names);
    for (int l = 0; l < XK_LEVELS; l++) {
        xkey *k;
        if (!names[l][0])
            continue;
        if ((k = key_get(d, names[l], l, now)) != NULL)
            key_outcome(d, k, ok, cls, now);
    }
}

static int seq_within(uint32_t x, uint32_t a, uint32_t b) { return x - a <= b - a; }

/* the client's first data: its host name (TLS SNI or HTTP Host:; other
 * flows get theirs from the address cache, which the detector only reads:
 * the profiles' host names stay what the engine itself learnt) */
static void learn_host(ct_flow *f, const gpkt *p)
{
    fstate *fs = fs_of(f);
    char h[256], n[256];
    int ip;
    if (fs->host_tried || !p->payload_len || f->proto != 6)
        return;
    fs->host_tried = 1;
    if (!l7_tls_host(p->payload, p->payload_len, h, sizeof(h), 1) &&
        !l7_http_host(p->payload, p->payload_len, h, sizeof(h)))
        return;
    ip = xhost_norm(h, n, sizeof(n));
    if (!n[0])
        return;
    free(f->chost);
    f->chost = xstrdup(n);
    f->chost_ip = (uint8_t)ip;
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

static void udp_packet(xdet *d, ct_flow *f, uint64_t now)
{
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
    d->packets++;
    keys_purge(d, now);
    f = ctrack_feed(d->ct, p, now, &reverse);
    if (!f || fs_of(f)->decided)
        return;
    if (!unicast(f)) {
        /* multicast and broadcast get no answer on their flow (mDNS,
         * SSDP), link-local is the LAN: no outcome */
        fs_of(f)->decided = 1;
        return;
    }
    if (p->l4 == LAYER_TCP && f->proto == 6)
        tcp_packet(d, f, reverse, p, now);
    else if (p->l4 == LAYER_UDP && f->proto == 17)
        udp_packet(d, f, now);
    else if (p->l4 == LAYER_NONE && (p->l4proto == 1 || p->l4proto == 58))
        icmp_packet(d, f, p, now);
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
