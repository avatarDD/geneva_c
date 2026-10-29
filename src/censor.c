#include "censor.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

/* ---- packets ------------------------------------------------------------- */

/* What the censors read from a packet, parsed the way scapy dissects it. */
typedef struct {
    int ver, alen;
    const uint8_t *src, *dst;
    int tcp, udp;
    const uint8_t *l4;
    size_t l4len;
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint16_t flags;
    uint8_t dataofs;
    const uint8_t *pl; /* TCP or UDP payload */
    size_t plen;
} view;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void wr32(uint8_t *p, uint32_t v) { wr16(p, (uint16_t)(v >> 16)), wr16(p + 2, (uint16_t)v); }

static int parse(const uint8_t *p, size_t len, view *v)
{
    size_t hl, tot;
    uint8_t proto;
    memset(v, 0, sizeof(*v));
    if (len < 1)
        return -1;
    v->ver = p[0] >> 4;
    if (v->ver == 4) {
        if (len < 20 || (p[0] & 15) < 5 || (size_t)(p[0] & 15) * 4 > len)
            return -1;
        hl = (size_t)(p[0] & 15) * 4;
        tot = rd16(p + 2);
        /* scapy: a short packet keeps what there is, a long one has padding */
        if (tot < hl || tot > len)
            tot = len;
        v->alen = 4;
        v->src = p + 12;
        v->dst = p + 16;
        proto = p[9];
        if (rd16(p + 6) & 0x1fff)
            return 0; /* a later fragment: no L4 header */
    } else if (v->ver == 6) {
        if (len < 40)
            return -1;
        hl = 40;
        tot = 40 + (size_t)rd16(p + 4);
        if (tot > len)
            tot = len;
        v->alen = 16;
        v->src = p + 8;
        v->dst = p + 24;
        proto = p[6]; /* extension headers are not followed */
    } else {
        return -1;
    }
    v->l4 = p + hl;
    v->l4len = tot - hl;
    if (proto == 6 && v->l4len >= 20) {
        size_t thl;
        v->tcp = 1;
        v->sport = rd16(v->l4);
        v->dport = rd16(v->l4 + 2);
        v->seq = rd32(v->l4 + 4);
        v->ack = rd32(v->l4 + 8);
        v->dataofs = v->l4[12] >> 4;
        v->flags = (uint16_t)((v->l4[12] & 1) << 8 | v->l4[13]);
        /* scapy treats a data offset below 5 as 5 */
        thl = v->dataofs < 5 ? 20 : (size_t)v->dataofs * 4;
        if (thl < v->l4len) {
            v->pl = v->l4 + thl;
            v->plen = v->l4len - thl;
        }
    } else if (proto == 17 && v->l4len >= 8) {
        v->udp = 1;
        v->sport = rd16(v->l4);
        v->dport = rd16(v->l4 + 2);
        v->pl = v->l4 + 8;
        v->plen = v->l4len - 8;
    }
    return 0;
}

static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s)
{
    for (size_t i = 0; i + 1 < n; i += 2)
        s += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1)
        s += (uint32_t)(p[n - 1] << 8);
    return s;
}

static uint32_t pseudo(int alen, const uint8_t *src, const uint8_t *dst, uint8_t proto, size_t len)
{
    uint32_t s = sum16(src, (size_t)alen, 0);
    s = sum16(dst, (size_t)alen, s);
    return s + proto + (uint32_t)(len >> 16) + (uint32_t)(len & 0xffff);
}

static uint16_t fold(uint32_t s)
{
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* The TCP checksum scapy would compute for the segment (censors 10 and 11
 * compare it with the one in the packet). */
static uint16_t tcp_csum(const view *v)
{
    uint32_t s = pseudo(v->alen, v->src, v->dst, 6, v->l4len);
    s = sum16(v->l4, 16, s);
    s = sum16(v->l4 + 18, v->l4len - 18, s);
    return fold(s);
}

enum { F_FIN = 0x01, F_SYN = 0x02, F_RST = 0x04, F_PSH = 0x08, F_ACK = 0x10 };

/* scapy's sprintf('%TCP.flags%') == "RA" and so on: exactly these flags */
#define FLAGS_ARE(v, f) ((v)->flags == (f))

static int has_word(const censor_cfg *cfg, const uint8_t *p, size_t n)
{
    for (int w = 0; w < cfg->nwords; w++) {
        size_t wl = strlen(cfg->words[w]);
        if (!wl || wl > n)
            continue;
        for (size_t i = 0; i + wl <= n; i++)
            if (p[i] == (uint8_t)cfg->words[w][0] && !memcmp(p + i, cfg->words[w], wl))
                return 1;
    }
    return 0;
}

/* ---- injected packets ---------------------------------------------------- */

static size_t ip_header(uint8_t *o, int ver, const uint8_t *src, const uint8_t *dst, uint8_t proto,
                        size_t l4len)
{
    /* scapy's defaults: TTL 64, ID 1, no flags */
    if (ver == 4) {
        memset(o, 0, 20);
        o[0] = 0x45;
        wr16(o + 2, (uint16_t)(20 + l4len));
        wr16(o + 4, 1);
        o[8] = 64;
        o[9] = proto;
        memcpy(o + 12, src, 4);
        memcpy(o + 16, dst, 4);
        wr16(o + 10, fold(sum16(o, 20, 0)));
        return 20;
    }
    memset(o, 0, 40);
    o[0] = 0x60;
    wr16(o + 4, (uint16_t)l4len);
    o[6] = proto;
    o[7] = 64;
    memcpy(o + 8, src, 16);
    memcpy(o + 24, dst, 16);
    return 40;
}

static size_t build_rst(uint8_t *o, int ver, const uint8_t *src, const uint8_t *dst, uint16_t sport,
                        uint16_t dport, uint32_t seq, uint32_t ack)
{
    int alen = ver == 4 ? 4 : 16;
    size_t hl = ip_header(o, ver, src, dst, 6, 20);
    uint8_t *t = o + hl;
    memset(t, 0, 20);
    wr16(t, sport);
    wr16(t + 2, dport);
    wr32(t + 4, seq);
    wr32(t + 8, ack);
    t[12] = 5 << 4;
    t[13] = F_RST;
    wr16(t + 14, 8192); /* scapy's default window */
    wr16(t + 16, fold(sum16(t, 20, pseudo(alen, src, dst, 6, 20))));
    return hl + 20;
}

typedef struct {
    censor_send_fn fn;
    void *ctx;
    int n;
} sender;

static void emit(sender *s, const uint8_t *p, size_t n)
{
    if (s->fn)
        s->fn(p, n, s->ctx);
    s->n++;
}

/* Geneva: IP(src=pkt.dst, dst=pkt.src)/TCP(sport=pkt.dport, dport=pkt.sport,
 * seq=pkt.ack, ack=pkt.seq+len(payload), flags="R") */
static void rst_client(sender *s, const view *v)
{
    uint8_t b[60];
    size_t n = build_rst(b, v->ver, v->dst, v->src, v->dport, v->sport, v->ack, v->seq + (uint32_t)v->plen);
    emit(s, b, n);
}

/* Geneva: IP(src=censor_ip, dst=pkt.dst)/TCP(sport=pkt.sport,
 * dport=pkt.dport, seq=pkt.seq, ack=pkt.ack, flags="R") */
static int rst_server(sender *s, const view *v, const uint8_t *censor_ip)
{
    uint8_t b[60];
    size_t n;
    if (!censor_ip)
        return -1;
    n = build_rst(b, v->ver, censor_ip, v->dst, v->sport, v->dport, v->seq, v->ack);
    emit(s, b, n);
    return 0;
}

/* ---- censor state -------------------------------------------------------- */

typedef struct {
    int alen;
    uint8_t a[16];
} addr;

typedef struct {
    int alen;
    uint8_t src[16], dst[16];
    uint16_t sport, dport;
    uint32_t seq;
    int refs;   /* censor 8b lists a TCB once per SYN that re-synchronized it */
    int resync; /* censors 10 and 11 */
} tcb;

enum { T_EMPTY = 0, T_SET, T_NONE }; /* Python's {} / filled dict / None */

/* a connection, the same in both directions */
typedef struct {
    uint8_t ver, proto;
    uint16_t pa, pb;
    uint8_t a[16], b[16];
} flowkey;

typedef struct {
    flowkey *v;
    size_t n, cap;
} flowset;

#define MAX_FLOWS 4096

typedef enum {
    M_1 = 1, M_2, M_3, M_4, M_5, M_6, M_7, M_8, M_8B, M_9, M_10, M_11, M_DNS
} model_id;

struct censor {
    model_id m;
    const char *name;
    censor_cfg cfg;
    /* censors 1-5: the next expected sequence number */
    uint32_t next;
    /* censors 6-9: the single TCB */
    int state;
    addr ips[2];
    uint16_t ports[2];
    tcb one;
    int resynchronize;
    /* censors 1, 4, 6-9 */
    addr drop_all;
    /* censors 8b, 10, 11 */
    tcb *tcbs;
    size_t ntcbs, captcbs;
    addr *flagged;
    size_t nflagged, capflagged;
    /* censor_new_run(): connections of this run and of the ones before */
    int runs;
    flowset seen, old;
};

static const struct {
    model_id id;
    const char *name;
    censor_info info;
} models[] = {
    {M_1, "1", {"1", "syncs on SYN, drops the packet and everything after from the client", 0}},
    {M_2, "2", {"2", "syncs on SYN, sends 5 RSTs to the client", 0}},
    {M_3, "3", {"3", "syncs on SYN, sends 5 RSTs to the client and 5 to the server", 0}},
    {M_4, "4", {"4", "syncs on SYN and on ACK, drops everything from the client", 0}},
    {M_5, "5", {"5", "syncs on SYN, sends 5 RSTs to the server", 0}},
    {M_6, "6", {"6", "checks every packet until any RST or FIN, drops everything from the client", 0}},
    {M_7, "7", {"7", "TCB on addresses and ports, torn down by RST or FIN; drops", 0}},
    {M_8, "8", {"8", "TCB on addresses, ports and sequence number, torn down by RST or FIN; drops", 0}},
    {M_8B, "8b", {"8b", "many TCBs, torn down by RST; RSTs both ways, blocks both hosts", 0}},
    {M_9, "9", {"9", "one TCB, re-synchronizes after RST or FIN; drops", 0}},
    {M_10, "10", {"10", "many TCBs, re-synchronize after RST or FIN, checksums checked; RSTs", 0}},
    {M_11, "11", {"11", "like 10, also syncs on ACK, ignores data offsets below 5", 0}},
    {M_DNS, "dns", {"dns", "answers DNS queries for forbidden names with a forged address first", 1}},
};

const censor_info *censor_models(size_t *n)
{
    static censor_info list[ARRAY_LEN(models) + 1];
    for (size_t i = 0; i < ARRAY_LEN(models); i++)
        list[i] = models[i].info;
    *n = ARRAY_LEN(models);
    return list;
}

void censor_cfg_default(censor_cfg *c)
{
    memset(c, 0, sizeof(*c));
    c->words[0] = "ultrasurf";
    c->nwords = 1;
    c->dns_a[0] = 10, c->dns_a[1] = 10, c->dns_a[2] = 34, c->dns_a[3] = 34;
    c->dns_aaaa[0] = 0x20, c->dns_aaaa[1] = 0x01, c->dns_aaaa[2] = 0x0d, c->dns_aaaa[3] = 0xb8;
    c->dns_aaaa[15] = 0x34;
    c->dns_ttl = 60;
    c->max_tcbs = 4096;
    c->spoof_client = 1;
}

censor *censor_new(const char *name, const censor_cfg *cfg, sbuf *err)
{
    censor *c;
    if (!strncmp(name, "censor", 6))
        name += 6;
    for (size_t i = 0; i < ARRAY_LEN(models); i++)
        if (!strcmp(name, models[i].name)) {
            c = xcalloc(1, sizeof(*c));
            c->m = models[i].id;
            c->name = models[i].name;
            c->cfg = *cfg;
            if (c->cfg.max_tcbs <= 0)
                c->cfg.max_tcbs = 4096;
            return c;
        }
    sb_printf(err, "unknown censor \"%s\" (1-11, 8b or dns)", name);
    return NULL;
}

void censor_reset(censor *c)
{
    c->next = 0;
    c->state = T_EMPTY;
    memset(c->ips, 0, sizeof(c->ips));
    memset(c->ports, 0, sizeof(c->ports));
    memset(&c->one, 0, sizeof(c->one));
    c->resynchronize = 0;
    memset(&c->drop_all, 0, sizeof(c->drop_all));
    c->ntcbs = 0;
    c->nflagged = 0;
}

static void flow_key(const view *v, flowkey *k)
{
    int swap = memcmp(v->src, v->dst, (size_t)v->alen);
    memset(k, 0, sizeof(*k));
    k->ver = (uint8_t)v->ver;
    k->proto = 6;
    if (!swap)
        swap = v->sport > v->dport ? 1 : -1;
    memcpy(k->a, swap < 0 ? v->src : v->dst, (size_t)v->alen);
    memcpy(k->b, swap < 0 ? v->dst : v->src, (size_t)v->alen);
    k->pa = swap < 0 ? v->sport : v->dport;
    k->pb = swap < 0 ? v->dport : v->sport;
}

static flowkey *flow_find(flowset *fs, const flowkey *k)
{
    for (size_t i = 0; i < fs->n; i++)
        if (!memcmp(&fs->v[i], k, sizeof(*k)))
            return &fs->v[i];
    return NULL;
}

static void flow_add(flowset *fs, const flowkey *k)
{
    if (flow_find(fs, k))
        return;
    if (fs->n == MAX_FLOWS) {
        memmove(fs->v, fs->v + 1, (fs->n - 1) * sizeof(*fs->v));
        fs->n--;
    }
    if (fs->n == fs->cap) {
        fs->cap = fs->cap ? fs->cap * 2 : 16;
        fs->v = xrealloc(fs->v, fs->cap * sizeof(*fs->v));
    }
    fs->v[fs->n++] = *k;
}

void censor_new_run(censor *c)
{
    censor_reset(c);
    c->runs = 1;
    for (size_t i = 0; i < c->seen.n; i++)
        flow_add(&c->old, &c->seen.v[i]);
    c->seen.n = 0;
}

/* Returns 1 for a packet of a connection from an earlier run. */
static int old_flow(censor *c, const view *v)
{
    flowkey k, *o;
    /* TCP only: a SYN tells a new connection on an old 4-tuple, and
     * leftovers of UDP do not change the DNS censor */
    if (!c->runs || !v->tcp)
        return 0;
    flow_key(v, &k);
    if ((o = flow_find(&c->old, &k)) != NULL) {
        if (!(v->tcp && FLAGS_ARE(v, F_SYN)))
            return 1;
        *o = c->old.v[--c->old.n]; /* reopened */
    }
    flow_add(&c->seen, &k);
    return 0;
}

void censor_free(censor *c)
{
    if (!c)
        return;
    free(c->seen.v);
    free(c->old.v);
    free(c->tcbs);
    free(c->flagged);
    free(c);
}

const char *censor_name(const censor *c) { return c->name; }

static void set_addr(addr *a, int alen, const uint8_t *p)
{
    a->alen = alen;
    memcpy(a->a, p, (size_t)alen);
}

static int addr_is(const addr *a, int alen, const uint8_t *p)
{
    return a->alen == alen && !memcmp(a->a, p, (size_t)alen);
}

static int is_flagged(const censor *c, const view *v)
{
    for (size_t i = 0; i < c->nflagged; i++)
        if (addr_is(&c->flagged[i], v->alen, v->src))
            return 1;
    return 0;
}

static void flag(censor *c, int alen, const uint8_t *p)
{
    for (size_t i = 0; i < c->nflagged; i++)
        if (addr_is(&c->flagged[i], alen, p))
            return;
    if (c->nflagged == c->capflagged) {
        if (c->capflagged >= 65536)
            return;
        c->capflagged = c->capflagged ? c->capflagged * 2 : 8;
        c->flagged = xrealloc(c->flagged, c->capflagged * sizeof(*c->flagged));
    }
    set_addr(&c->flagged[c->nflagged++], alen, p);
}

static int tuple_is(const tcb *t, const view *v)
{
    return t->alen == v->alen && !memcmp(t->src, v->src, (size_t)v->alen) &&
           !memcmp(t->dst, v->dst, (size_t)v->alen) && t->sport == v->sport && t->dport == v->dport;
}

/* get_matching_tcb: the 4-tuple and the expected sequence number */
static tcb *matching(censor *c, const view *v)
{
    for (size_t i = 0; i < c->ntcbs; i++)
        if (tuple_is(&c->tcbs[i], v) && c->tcbs[i].seq == v->seq)
            return &c->tcbs[i];
    return NULL;
}

/* get_partial_tcb: the 4-tuple only */
static tcb *partial(censor *c, const view *v)
{
    for (size_t i = 0; i < c->ntcbs; i++)
        if (tuple_is(&c->tcbs[i], v))
            return &c->tcbs[i];
    return NULL;
}

static tcb *new_tcb(censor *c, const view *v)
{
    tcb *t;
    if (c->ntcbs == (size_t)c->cfg.max_tcbs) {
        /* forget the oldest connection */
        memmove(c->tcbs, c->tcbs + 1, (c->ntcbs - 1) * sizeof(*c->tcbs));
        c->ntcbs--;
    }
    if (c->ntcbs == c->captcbs) {
        c->captcbs = c->captcbs ? c->captcbs * 2 : 16;
        c->tcbs = xrealloc(c->tcbs, c->captcbs * sizeof(*c->tcbs));
    }
    t = &c->tcbs[c->ntcbs++];
    memset(t, 0, sizeof(*t));
    t->alen = v->alen;
    memcpy(t->src, v->src, (size_t)v->alen);
    memcpy(t->dst, v->dst, (size_t)v->alen);
    t->sport = v->sport;
    t->dport = v->dport;
    t->seq = v->seq;
    return t;
}

static void del_tcb(censor *c, tcb *t)
{
    size_t i = (size_t)(t - c->tcbs);
    if (--t->refs > 0)
        return;
    memmove(c->tcbs + i, c->tcbs + i + 1, (c->ntcbs - i - 1) * sizeof(*c->tcbs));
    c->ntcbs--;
}

static int in_pair_addr(const addr *pair, const view *v, const uint8_t *p)
{
    return addr_is(&pair[0], v->alen, p) || addr_is(&pair[1], v->alen, p);
}

static int in_pair_port(const uint16_t *pair, uint16_t p) { return pair[0] == p || pair[1] == p; }

/* ---- check_censor() of each model ---------------------------------------- */

enum { NO = 0, HIT = 1, BLOCKED = 2 };

#define WORDS(c, v) (has_word(&(c)->cfg, (v)->pl, (v)->plen) ? HIT : NO)

/* censors 1-5: one sequence number, synchronized on the SYN (4: and ACK) */
static int check_seq(censor *c, const view *v, int drop_all, int sync_ack)
{
    if (drop_all && addr_is(&c->drop_all, v->alen, v->src))
        return BLOCKED;
    if (!v->tcp)
        return NO;
    if (FLAGS_ARE(v, F_SYN)) {
        c->next = v->seq + 1;
        return NO;
    }
    if (sync_ack && FLAGS_ARE(v, F_ACK)) {
        c->next = v->seq;
        return NO;
    }
    if (v->seq != c->next)
        return NO;
    c->next += (uint32_t)v->plen;
    return WORDS(c, v);
}

static int check6(censor *c, const view *v)
{
    if (addr_is(&c->drop_all, v->alen, v->src))
        return BLOCKED;
    if (!v->tcp)
        return NO;
    if (FLAGS_ARE(v, F_RST) || FLAGS_ARE(v, F_RST | F_ACK) || FLAGS_ARE(v, F_FIN)) {
        c->state = T_NONE;
        return NO;
    }
    if (c->state == T_NONE)
        return NO;
    return WORDS(c, v);
}

static int pair_matches(const censor *c, const view *v)
{
    return c->state == T_SET && in_pair_addr(c->ips, v, v->src) && in_pair_addr(c->ips, v, v->dst) &&
           in_pair_port(c->ports, v->dport) && in_pair_port(c->ports, v->sport);
}

static void set_pair(censor *c, const view *v)
{
    set_addr(&c->ips[0], v->alen, v->src);
    set_addr(&c->ips[1], v->alen, v->dst);
    c->ports[0] = v->sport;
    c->ports[1] = v->dport;
    c->state = T_SET;
}

static int check7(censor *c, const view *v)
{
    if (addr_is(&c->drop_all, v->alen, v->src))
        return BLOCKED;
    if (!v->tcp)
        return NO;
    if (FLAGS_ARE(v, F_RST) || FLAGS_ARE(v, F_RST | F_ACK) || FLAGS_ARE(v, F_FIN)) {
        if (pair_matches(c, v)) {
            c->state = T_NONE;
            return NO;
        }
    } else if (c->state == T_EMPTY) {
        set_pair(c, v);
    }
    if (c->state == T_NONE)
        return NO;
    return WORDS(c, v);
}

static int check8(censor *c, const view *v)
{
    if (addr_is(&c->drop_all, v->alen, v->src))
        return BLOCKED;
    if (!v->tcp)
        return NO;
    if (FLAGS_ARE(v, F_SYN) && c->state == T_EMPTY) {
        set_pair(c, v);
        c->one.seq = v->seq + 1;
        return NO;
    } else if (FLAGS_ARE(v, F_RST) || FLAGS_ARE(v, F_FIN)) {
        if (pair_matches(c, v) && v->seq == c->one.seq) {
            c->state = T_NONE;
            return NO;
        }
    }
    if (c->state == T_NONE)
        return NO;
    if (c->state == T_SET && v->seq == c->one.seq)
        c->one.seq += (uint32_t)v->plen;
    return WORDS(c, v);
}

static int check8b(censor *c, const view *v)
{
    tcb *t;
    if (is_flagged(c, v))
        return BLOCKED;
    if (!v->tcp || v->dataofs < 5)
        return NO;
    t = matching(c, v);
    if (!t && FLAGS_ARE(v, F_SYN)) {
        /* an existing TCB of this tuple keeps its own sequence number: the
         * Python code only adds 1 to it (and lists it once more) */
        t = partial(c, v);
        if (!t)
            t = new_tcb(c, v);
        t->seq += 1;
        t->refs++;
        return NO;
    } else if (t && (FLAGS_ARE(v, F_RST) || FLAGS_ARE(v, F_RST | F_ACK))) {
        del_tcb(c, t);
        return NO;
    }
    if (!t)
        return NO;
    t->seq += (uint32_t)v->plen;
    return WORDS(c, v);
}

static int tcb9_matches(const censor *c, const view *v)
{
    return c->state != T_SET || (tuple_is(&c->one, v) && v->seq == c->one.seq);
}

static int check9(censor *c, const view *v)
{
    if (addr_is(&c->drop_all, v->alen, v->src))
        return BLOCKED;
    if (!v->tcp)
        return NO;
    if (c->resynchronize || (c->state != T_SET && FLAGS_ARE(v, F_SYN))) {
        tcb *t = &c->one;
        t->alen = v->alen;
        memcpy(t->src, v->src, (size_t)v->alen);
        memcpy(t->dst, v->dst, (size_t)v->alen);
        t->sport = v->sport;
        t->dport = v->dport;
        t->seq = v->seq + (FLAGS_ARE(v, F_SYN) ? 1 : (uint32_t)v->plen);
        c->state = T_SET;
        c->resynchronize = 0;
        return WORDS(c, v);
    } else if (tcb9_matches(c, v) && (FLAGS_ARE(v, F_RST) || FLAGS_ARE(v, F_FIN))) {
        c->resynchronize = 1;
    }
    if (!tcb9_matches(c, v))
        return NO;
    if (c->state == T_SET)
        c->one.seq += (uint32_t)v->plen;
    return WORDS(c, v);
}

/* censors 10 and 11 */
static int check10(censor *c, const view *v, int is11)
{
    tcb *t;
    uint16_t f = v->flags;
    if (is_flagged(c, v))
        return BLOCKED;
    if (!v->tcp)
        return NO;
    if (is11 && v->dataofs < 5)
        return NO;
    if (rd16(v->l4 + 16) != tcp_csum(v))
        return NO;
    t = matching(c, v);
    if ((t && t->resync) || (!t && (f == F_SYN || (is11 && f == F_ACK)))) {
        if (!t || is11)
            t = partial(c, v);
        if (!t)
            t = new_tcb(c, v);
        t->seq = v->seq + (f == F_SYN ? 1 : (uint32_t)v->plen);
        t->refs = 1;
        t->resync = 0;
        return NO;
    } else if (t && (f == F_RST || f == F_FIN ||
                     (is11 && (f == (F_RST | F_ACK) || f == (F_FIN | F_ACK))))) {
        t->resync = 1;
    }
    if (!t)
        return NO;
    t->seq += (uint32_t)v->plen;
    return WORDS(c, v);
}

/* ---- DNS ----------------------------------------------------------------- */

static int lower(int ch) { return ch >= 'A' && ch <= 'Z' ? ch + 32 : ch; }

/* Reads the first question's name the naive way: compression pointers are
 * not followed, so a compressed query is not recognized. Returns the length
 * of the question (name, type, class) or 0. */
static size_t dns_qname(const uint8_t *p, size_t n, char *name, size_t cap)
{
    size_t off = 12, out = 0;
    while (off < n) {
        uint8_t l = p[off];
        if (!l) {
            name[out] = 0;
            return off + 1 + 4 <= n ? off + 1 + 4 - 12 : 0;
        }
        if (l & 0xc0 || off + 1 + l > n || out + l + 2 > cap)
            return 0;
        if (out)
            name[out++] = '.';
        for (size_t i = 0; i < l; i++)
            name[out++] = (char)lower(p[off + 1 + i]);
        off += 1u + l;
    }
    return 0;
}

static int name_has_word(const censor_cfg *cfg, const char *name)
{
    for (int w = 0; w < cfg->nwords; w++) {
        const char *word = cfg->words[w];
        size_t wl = strlen(word), nl = strlen(name);
        for (size_t i = 0; wl && i + wl <= nl; i++) {
            size_t k = 0;
            while (k < wl && name[i + k] == lower((uint8_t)word[k]))
                k++;
            if (k == wl)
                return 1;
        }
    }
    return 0;
}

static int dns_inject(censor *c, const view *v, sender *s)
{
    char name[256];
    uint8_t b[40 + 8 + 12 + 260 + 16 + 16], *u, *d;
    size_t qlen, dl, hl;
    uint16_t qtype;
    if (!v->udp || v->plen < 12)
        return NO;
    if (v->pl[2] & 0x80 || rd16(v->pl + 4) < 1)
        return NO; /* an answer, or no question */
    qlen = dns_qname(v->pl, v->plen, name, sizeof(name));
    if (!qlen || !name_has_word(&c->cfg, name))
        return NO;
    qtype = rd16(v->pl + 12 + qlen - 4);
    hl = v->ver == 4 ? 20 : 40;
    u = b + hl;
    d = u + 8;
    memcpy(d, v->pl, 2); /* id */
    wr16(d + 2, (uint16_t)(0x8080 | (v->pl[2] & 0x01) << 8)); /* QR, RD from the query, RA */
    wr16(d + 4, 1);
    wr16(d + 6, 1);
    wr16(d + 8, 0);
    wr16(d + 10, 0);
    memcpy(d + 12, v->pl + 12, qlen);
    dl = 12 + qlen;
    wr16(d + dl, 0xc00c);
    wr16(d + dl + 2, qtype == 28 ? 28 : 1);
    wr16(d + dl + 4, 1);
    wr32(d + dl + 6, c->cfg.dns_ttl);
    if (qtype == 28) {
        wr16(d + dl + 10, 16);
        memcpy(d + dl + 12, c->cfg.dns_aaaa, 16);
        dl += 12 + 16;
    } else {
        wr16(d + dl + 10, 4);
        memcpy(d + dl + 12, c->cfg.dns_a, 4);
        dl += 12 + 4;
    }
    ip_header(b, v->ver, v->dst, v->src, 17, 8 + dl);
    wr16(u, v->dport);
    wr16(u + 2, v->sport);
    wr16(u + 4, (uint16_t)(8 + dl));
    wr16(u + 6, 0);
    {
        uint16_t cs = fold(sum16(u, 8 + dl, pseudo(v->alen, v->dst, v->src, 17, 8 + dl)));
        wr16(u + 6, cs ? cs : 0xffff);
    }
    emit(s, b, hl + 8 + dl);
    return HIT;
}

/* ---- censor() of each model ---------------------------------------------- */

static const uint8_t *censor_ip(censor *c, const view *v, uint8_t *buf)
{
    if (c->cfg.spoof_client)
        return v->src;
    if (v->ver == 4 && c->cfg.has_ip4)
        return c->cfg.ip4;
    if (v->ver == 6 && c->cfg.has_ip6)
        return c->cfg.ip6;
    if (c->cfg.local_addr && c->cfg.local_addr(v->ver, v->dst, buf, c->cfg.local_ctx) == 0)
        return buf;
    return NULL;
}

void censor_packet(censor *c, const uint8_t *pkt, size_t len, censor_send_fn send, void *ctx,
                   censor_result *r)
{
    view v;
    sender s = {send, ctx, 0};
    int hit = NO;
    uint8_t ipbuf[16];
    const uint8_t *cip;

    memset(r, 0, sizeof(*r));
    r->accept = 1;
    if (parse(pkt, len, &v) < 0)
        return;
    if (v.tcp && v.sport == 2222 && v.seq == 13337) {
        r->accept = 0;
        r->what = CENSOR_CONTROL;
        return;
    }
    if (old_flow(c, &v)) {
        r->what = CENSOR_OLD;
        return;
    }
    switch (c->m) {
    case M_1: hit = check_seq(c, &v, 1, 0); break;
    case M_2:
    case M_3:
    case M_5: hit = check_seq(c, &v, 0, 0); break;
    case M_4: hit = check_seq(c, &v, 1, 1); break;
    case M_6: hit = check6(c, &v); break;
    case M_7: hit = check7(c, &v); break;
    case M_8: hit = check8(c, &v); break;
    case M_8B: hit = check8b(c, &v); break;
    case M_9: hit = check9(c, &v); break;
    case M_10: hit = check10(c, &v, 0); break;
    case M_11: hit = check10(c, &v, 1); break;
    case M_DNS: hit = dns_inject(c, &v, &s); break;
    }
    if (hit == NO)
        return;
    r->what = hit == HIT ? CENSOR_FIRED : CENSOR_BLOCKED;
    switch (c->m) {
    case M_1:
    case M_4:
    case M_6:
    case M_7:
    case M_8:
    case M_9:
        set_addr(&c->drop_all, v.alen, v.src);
        r->accept = 0;
        r->action = "drop";
        break;
    case M_2:
        for (int i = 0; i < 5; i++)
            rst_client(&s, &v);
        r->action = "rst";
        break;
    case M_3:
        cip = censor_ip(c, &v, ipbuf);
        for (int i = 0; i < 5; i++) {
            rst_client(&s, &v);
            rst_server(&s, &v, cip);
        }
        r->action = "rst";
        break;
    case M_5:
        cip = censor_ip(c, &v, ipbuf);
        for (int i = 0; i < 5; i++)
            rst_server(&s, &v, cip);
        r->action = "rst";
        break;
    case M_8B:
    case M_10:
    case M_11:
        flag(c, v.alen, v.src);
        flag(c, v.alen, v.dst);
        r->action = "rst";
        if (!v.tcp)
            break; /* Geneva fails on a non-TCP packet here and lets it be */
        cip = censor_ip(c, &v, ipbuf);
        for (int i = 0; i < 5; i++) {
            rst_client(&s, &v);
            rst_server(&s, &v, cip);
        }
        break;
    case M_DNS:
        r->action = "dns";
        break;
    }
    r->sent = s.n;
}
