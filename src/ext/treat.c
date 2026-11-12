/*
 * The treatment of --ext-auto propose|apply (treat.h).
 */
#include "treat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "plat.h"
#include "tuner.h"

/* ---- the portfolio ------------------------------------------------------------- */

/* The arms by class (bit XC_*), tried in this order of the index when
 * their draws tie. TCP: the request or the ClientHello cut so that a
 * per-packet DPI misses the name or the word (14, 18, 19), sent last
 * first (15), or in IP fragments (20). UDP: a fake Initial first (16),
 * fragments. */
#define TCP_CLASSES                                                                                                \
    (1u << XC_RETRANS | 1u << XC_RST_IN | 1u << XC_RST_INJECT | 1u << XC_REDIRECT | 1u << XC_FREEZE |            \
     1u << XC_THROTTLE)
#define UDP_CLASSES (1u << XC_UDP_NOANSWER)

static const struct {
    const char *text;
    unsigned classes;
    uint8_t proto;
} portfolio[] = {
    {"[TCP:flags:PA]-xsplit{pos=1}-| \\/", TCP_CLASSES, 6},
    {"[TCP:flags:PA]-xdisorder{pos=1,midsld}-| \\/", TCP_CLASSES, 6},
    {"[TCP:flags:PA]-xsplit{pos=method+2}-| \\/", TCP_CLASSES, 6},
    {"[TCP:flags:PA]-xsplit{pos=2,6,10,14,18,22,26,30}-| \\/", TCP_CLASSES, 6},
    {"[TCP:flags:PA]-xsend{ipfrag;ipfrag_pos_tcp=24}(drop,)-| \\/", TCP_CLASSES, 6},
    {"[UDP:dport:443]-xfake{blob=fake_quic_initial;repeats=2}-| \\/", UDP_CLASSES, 17},
    {"[UDP:dport:443]-xsend{ipfrag;ipfrag_pos_udp=8}(drop,)-| \\/", UDP_CLASSES, 17},
};
#define NARMS (sizeof(portfolio) / sizeof(*portfolio))

#define MAX_KEYS 4096
#define NBUCKETS 1024
#define NFLOWS 4096       /* connections waiting for their outcome */
#define GAMMA 0.98        /* the discount of older outcomes */
#define P_BEST 0.95       /* TREAT: P(the arm is the best) ... */
#define MIN_SUCC 3        /* ... and its successes */
#define GOOD 0.75         /* or its posterior mean (several arms work) */
#define DRAWS 200         /* the Monte Carlo draws of P(best) */
#define CUSUM_K 0.3       /* CUSUM: the failure rate a treated key may have */
#define CUSUM_H 2.0       /* ... and the alarm */
#define TRIES 2           /* UNTREATABLE: every arm this many times, no success */
#define RETRY_S 60        /* the first recheck; doubled up to 64 times */
#define RETRY_MAX 6

enum { S_PROPOSED = 1, S_TRIAL, S_TREAT, S_UNTREATABLE };
static const char *const state_name[] = {"", "proposed", "trial", "treat", "untreatable"};

typedef struct trec {
    struct trec *next;
    char *name;
    int level, cls, state;
    double A[NARMS], B[NARMS];
    unsigned tries[NARMS], succ[NARMS];
    int treat;      /* the arm of TREAT (index) */
    double cusum;
    unsigned backoff;
    uint64_t retry_at; /* UNTREATABLE: the recheck, ms */
    uint64_t prop_id;
    uint32_t khash;
} trec;

/* a connection's arm, for its outcome (by the client's tuple) */
typedef struct {
    trec *r;
    uint32_t epoch; /* the record's khash when drawn: older outcomes do not count */
    int arm;
    uint8_t ver, proto;
    uint8_t cli[16], srv[16];
    uint16_t cport, sport;
} tflow;

static struct {
    int mode;
    plat_mutex_t lock;
    strategy *arm[NARMS];
    trec *b[NBUCKETS];
    size_t n;
    tflow fl[NFLOWS];
    int live;          /* keys in TRIAL or TREAT ... */
    volatile int any;  /* ... > 0: the workers' check without the lock */
    int full_told;
} g;

/* every change of a record's state (under the lock) */
static void set_state(trec *r, int st)
{
    int was = r->state == S_TRIAL || r->state == S_TREAT, is = st == S_TRIAL || st == S_TREAT;
    r->state = st;
    if (was != is) {
        g.live += is - was;
        atomic_store_int(&g.any, g.live > 0);
    }
}

static uint32_t hash32(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++)
        h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

int xtreat_start(int mode, sbuf *err)
{
    xtreat_stop();
    if (mode == XTR_OFF)
        return 0;
    for (size_t i = 0; i < NARMS; i++) {
        sbuf e;
        sb_init(&e);
        g.arm[i] = strategy_parse(portfolio[i].text, &e);
        if (!g.arm[i]) {
            sb_printf(err, "the portfolio's arm %zu: %s", i + 1, e.data);
            sb_free(&e);
            xtreat_stop();
            return -1;
        }
        sb_free(&e);
    }
    plat_mutex_init(&g.lock);
    g.mode = mode;
    return 0;
}

void xtreat_stop(void)
{
    if (!g.mode)
        return;
    for (size_t i = 0; i < NARMS; i++)
        strategy_free(g.arm[i]);
    for (int i = 0; i < NBUCKETS; i++)
        for (trec *r = g.b[i], *n; r; r = n) {
            n = r->next;
            free(r->name);
            free(r);
        }
    plat_mutex_destroy(&g.lock);
    memset(&g, 0, sizeof(g));
}

int xtreat_mode(void) { return g.mode; }
size_t xtreat_narms(void) { return g.mode ? NARMS : 0; }
strategy *xtreat_arm(size_t i) { return g.mode && i < NARMS ? g.arm[i] : NULL; }

static trec *find(const char *name)
{
    for (trec *r = g.b[hash32(name) % NBUCKETS]; r; r = r->next)
        if (!strcmp(r->name, name))
            return r;
    return NULL;
}

static int arm_of(const trec *r, size_t i) { return portfolio[i].classes >> r->cls & 1; }

static unsigned class_arms(int cls)
{
    unsigned m = 0;
    for (size_t i = 0; i < NARMS; i++)
        m |= (unsigned)(portfolio[i].classes >> cls & 1) << i;
    return m;
}

static size_t arms_of(int cls)
{
    size_t n = 0;
    for (size_t i = 0; i < NARMS; i++)
        n += portfolio[i].classes >> cls & 1;
    return n;
}

/* ---- events (after the lock) ------------------------------------------------------- */

typedef struct {
    char name[300];
    int state, cls, arm;
    unsigned retry_s;
    uint64_t pid;
    const char *why;
} tnews;

static void news_of(tnews *nw, const trec *r, const char *why)
{
    snprintf(nw->name, sizeof(nw->name), "%s", r->name);
    nw->state = r->state;
    nw->cls = r->cls;
    nw->arm = r->state == S_TREAT ? r->treat : -1;
    nw->retry_s = r->state == S_UNTREATABLE ? (unsigned)(RETRY_S << (r->backoff ? r->backoff - 1 : 0)) : 0;
    nw->pid = r->state == S_PROPOSED ? r->prop_id : 0;
    nw->why = why;
}

static void tell(const tnews *nw)
{
    if (!nw->state)
        return;
    if (nw->arm >= 0)
        LOGI("treat", "%s: %s on arm %d (%s): %s", nw->name, state_name[nw->state], nw->arm + 1,
             portfolio[nw->arm].text, nw->why);
    else
        LOGI("treat", "%s: %s (%s): %s", nw->name, state_name[nw->state], xdet_class_name(nw->cls), nw->why);
    if (!ev_enabled())
        return;
    if (nw->pid) {
        ev_t e;
        ev_begin(&e, "ext_proposal");
        jw_kuint(&e.w, "id", nw->pid);
        jw_kstr(&e.w, "key", nw->name);
        jw_kstr(&e.w, "kind", "treat");
        jw_kstr(&e.w, "class", xdet_class_name(nw->cls));
        jw_kuint(&e.w, "arms", arms_of(nw->cls));
        ev_emit(&e);
    }
    {
        ev_t e;
        ev_begin(&e, "ext_treat");
        jw_kstr(&e.w, "key", nw->name);
        jw_kstr(&e.w, "state", state_name[nw->state]);
        jw_kstr(&e.w, "class", xdet_class_name(nw->cls));
        if (nw->arm >= 0) {
            jw_kint(&e.w, "arm", nw->arm + 1);
            jw_kstr(&e.w, "strategy", portfolio[nw->arm].text);
        }
        if (nw->retry_s)
            jw_kuint(&e.w, "retry_s", nw->retry_s);
        jw_kstr(&e.w, "why", nw->why);
        ev_emit(&e);
    }
}

/* ---- the states ------------------------------------------------------------------------ */

static void trial(trec *r)
{
    set_state(r, S_TRIAL);
    memset(r->A, 0, sizeof(r->A));
    memset(r->B, 0, sizeof(r->B));
    memset(r->tries, 0, sizeof(r->tries));
    memset(r->succ, 0, sizeof(r->succ));
    r->cusum = 0;
    r->khash++; /* the connections draw again */
}

static void untreatable(trec *r, uint64_t now)
{
    set_state(r, S_UNTREATABLE);
    if (r->backoff < RETRY_MAX + 1)
        r->backoff++;
    r->retry_at = now + ((uint64_t)RETRY_S * 1000 << (r->backoff - 1));
    r->khash++;
}

/* A full table: a record out of the treatment (healthy again) makes room,
 * 1; 0: every key is in it */
static int evict(void)
{
    for (int i = 0; i < NBUCKETS; i++)
        for (trec **pp = &g.b[i], *r; (r = *pp) != NULL; pp = &r->next)
            if (!r->state) {
                *pp = r->next;
                for (int k = 0; k < NFLOWS; k++)
                    if (g.fl[k].r == r)
                        g.fl[k].r = NULL;
                free(r->name);
                free(r);
                g.n--;
                return 1;
            }
    if (!g.full_told) {
        g.full_told = 1;
        LOGW("treat", "%d keys in treatment: no more until one is healthy again", MAX_KEYS);
    }
    return 0;
}

/* the key is new to the treatment, or its class changed */
static void begin(trec *r, uint64_t now, tnews *nw)
{
    r->backoff = 0;
    r->retry_at = 0;
    if (!arms_of(r->cls)) {
        untreatable(r, now);
        news_of(nw, r, "no arm for the class");
    } else if (g.mode == XTR_PROPOSE) {
        set_state(r, S_PROPOSED);
        r->prop_id = xtune_new_id();
        news_of(nw, r, "waits for ext_approve");
    } else {
        trial(r);
        news_of(nw, r, "the arms of the class in turn");
    }
}

int xtreat_key(const xdet_key_ev *ev, uint64_t now_ms)
{
    trec *r;
    tnews nw;
    int owned;
    if (!g.mode || (ev->level != XK_IP && ev->level != XK_HOST))
        return 0;
    memset(&nw, 0, sizeof(nw));
    plat_mutex_lock(&g.lock);
    r = find(ev->key);
    if (!r && ev->impaired && (g.n < MAX_KEYS || evict())) {
        unsigned h = hash32(ev->key) % NBUCKETS;
        r = xcalloc(1, sizeof(*r));
        r->name = xstrdup(ev->key);
        r->level = ev->level;
        r->cls = ev->cls;
        r->next = g.b[h];
        g.b[h] = r;
        g.n++;
        begin(r, now_ms, &nw);
    } else if (r && ev->impaired && !r->state) {
        /* impaired again after it was healthy untreated */
        r->cls = ev->cls;
        begin(r, now_ms, &nw);
    } else if (r && ev->impaired && ev->cls != r->cls) {
        /* another class: the same arms go on (TCP's classes share them);
         * other arms begin anew, but a treated key keeps its arm until
         * CUSUM says it fails */
        int other = class_arms(ev->cls) != class_arms(r->cls);
        r->cls = ev->cls;
        if (other && r->state != S_TREAT && r->retry_at != UINT64_MAX)
            begin(r, now_ms, &nw);
    } else if (r && !ev->impaired && (r->state == S_PROPOSED || r->state == S_UNTREATABLE)) {
        /* healthy without the treatment: it is no longer needed */
        set_state(r, 0);
        r->prop_id = 0;
    }
    owned = r && r->state;
    plat_mutex_unlock(&g.lock);
    tell(&nw);
    return owned;
}

/* the record whose arms flow f runs: its host name's, else its address's */
static trec *rec_of(const ct_flow *f, const char *host)
{
    char names[XK_LEVELS][300];
    trec *r;
    xdet_flow_keys(f, host, names);
    if (names[XK_HOST][0] && (r = find(names[XK_HOST])) && (r->state == S_TRIAL || r->state == S_TREAT))
        return r;
    r = find(names[XK_IP]);
    return r && (r->state == S_TRIAL || r->state == S_TREAT) ? r : NULL;
}

/* Thompson's draw over the class's arms (of protocol proto, 0 any) */
static int draw(const trec *r, int proto)
{
    double best = -1;
    int arm = -1;
    for (size_t i = 0; i < NARMS; i++) {
        double x;
        if (!arm_of(r, i) || (proto && portfolio[i].proto != proto))
            continue;
        x = xtune_beta(1.0 + r->A[i], 1.0 + r->B[i]);
        if (x > best)
            best = x, arm = (int)i;
    }
    return arm;
}

static unsigned flow_slot(uint8_t ver, uint8_t proto, const uint8_t *cli, const uint8_t *srv, uint16_t cport,
                          uint16_t sport)
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 16; i++)
        h = ((h ^ cli[i]) * 16777619u ^ srv[i]) * 16777619u;
    h = ((h ^ cport) * 16777619u ^ sport) * 16777619u;
    return (h ^ ver ^ (uint32_t)proto << 8) % NFLOWS;
}

int xtreat_flow(ct_flow *f, const char *host, uint64_t now_ms)
{
    trec *r;
    int arm = -1;
    (void)now_ms;
    if (!g.mode || !f || (f->proto != 6 && f->proto != 17) || !atomic_load_int(&g.any))
        return -1;
    plat_mutex_lock(&g.lock);
    r = rec_of(f, host && *host ? host : f->chost);
    if (r) {
        uint32_t kh = hash32(r->name) + r->khash;
        if (f->xr_arm && f->xr_khash == kh) {
            arm = f->xr_arm - 1;
        } else {
            tflow *t;
            /* a treated key's arm, for the connections of its protocol
             * (an address's other protocol goes untreated) */
            if (r->state == S_TREAT)
                arm = portfolio[r->treat].proto == f->proto ? r->treat : -1;
            else
                arm = draw(r, f->proto);
            if (arm >= 0) {
                f->xr_arm = (uint8_t)(arm + 1);
                f->xr_khash = kh;
                /* the connection's outcome comes by its tuple */
                t = &g.fl[flow_slot(f->ver, f->proto, f->cli, f->srv, f->cport, f->sport)];
                t->r = r;
                t->epoch = r->khash;
                t->arm = arm;
                t->ver = f->ver;
                t->proto = f->proto;
                memcpy(t->cli, f->cli, 16);
                memcpy(t->srv, f->srv, 16);
                t->cport = f->cport;
                t->sport = f->sport;
                LOGD("treat", "%s: the connection from port %u runs arm %d", r->name, f->cport, arm + 1);
            }
        }
    }
    plat_mutex_unlock(&g.lock);
    return arm;
}

/* P(each arm is the best one): the most likely and its probability */
static int best_of(const trec *r, double *p)
{
    unsigned wins[NARMS] = {0};
    int top = -1;
    for (int k = 0; k < DRAWS; k++) {
        int a = draw(r, 0);
        if (a >= 0)
            wins[a]++;
    }
    for (size_t i = 0; i < NARMS; i++)
        if (arm_of(r, i) && (top < 0 || wins[i] > wins[top]))
            top = (int)i;
    *p = top >= 0 ? (double)wins[top] / DRAWS : 0;
    return top;
}

/* Several arms may work as well (P(best) then stays low): the one with
 * the highest posterior mean, if it is at least GOOD and the arm has its
 * successes; -1 none */
static int good_enough(const trec *r)
{
    int top = -1;
    double m = 0;
    for (size_t i = 0; i < NARMS; i++) {
        double x = (1.0 + r->A[i]) / (2.0 + r->A[i] + r->B[i]);
        if (arm_of(r, i) && r->succ[i] >= MIN_SUCC && x >= GOOD && x > m)
            m = x, top = (int)i;
    }
    return top;
}

static void count(trec *r, int arm, int ok, uint64_t now, tnews *nw)
{
    double p;
    int best;
    for (size_t i = 0; i < NARMS; i++) {
        r->A[i] *= GAMMA;
        r->B[i] *= GAMMA;
    }
    if (ok)
        r->A[arm] += 1, r->succ[arm]++;
    else
        r->B[arm] += 1;
    r->tries[arm]++;
    if (ok)
        r->backoff = 0;
    if (r->state == S_TREAT) {
        if (arm != r->treat)
            return;
        /* CUSUM of the failures over what a working arm may lose */
        r->cusum = r->cusum + (ok ? 0.0 : 1.0) - CUSUM_K;
        if (r->cusum < 0)
            r->cusum = 0;
        if (r->cusum >= CUSUM_H) {
            /* the censor changed: what the arms did is of the past */
            trial(r);
            news_of(nw, r, "CUSUM: the treated arm fails now");
        }
        return;
    }
    if (r->state != S_TRIAL)
        return;
    best = best_of(r, &p);
    if (best < 0 || p < P_BEST || r->succ[best] < MIN_SUCC)
        best = good_enough(r);
    if (best >= 0 && r->succ[best] >= MIN_SUCC) {
        set_state(r, S_TREAT);
        r->treat = best;
        r->cusum = 0;
        r->khash++;
        news_of(nw, r, "the best arm");
        return;
    }
    {
        unsigned succ = 0;
        int all = 1;
        for (size_t i = 0; i < NARMS; i++)
            if (arm_of(r, i)) {
                succ += r->succ[i];
                all &= r->tries[i] >= TRIES;
            }
        if (all && !succ) {
            untreatable(r, now);
            news_of(nw, r, "every arm failed");
        }
    }
}

void xtreat_outcome(const xdet_flow_ev *ev, uint64_t now_ms)
{
    const ct_flow *f = ev->f;
    tflow *t;
    tnews nw;
    /* a provisional success (the key waits for the stricter one): the
     * flow's next event decides */
    if (!g.mode || !f || (ev->ok && ev->provisional))
        return;
    memset(&nw, 0, sizeof(nw));
    plat_mutex_lock(&g.lock);
    t = &g.fl[flow_slot(f->ver, f->proto, f->cli, f->srv, f->cport, f->sport)];
    if (t->r && t->ver == f->ver && t->proto == f->proto && t->cport == f->cport && t->sport == f->sport &&
        !memcmp(t->cli, f->cli, 16) && !memcmp(t->srv, f->srv, 16)) {
        LOGD("treat", "%s: arm %d %s", t->r->name, t->arm + 1, ev->ok ? "succeeded" : "failed");
        if ((t->r->state == S_TRIAL || t->r->state == S_TREAT) && t->epoch == t->r->khash)
            count(t->r, t->arm, ev->ok, now_ms, &nw);
        t->r = NULL;
    }
    plat_mutex_unlock(&g.lock);
    tell(&nw);
}

void xtreat_tick(uint64_t now_ms)
{
    tnews nw[4];
    size_t k = 0;
    if (!g.mode)
        return;
    memset(nw, 0, sizeof(nw));
    plat_mutex_lock(&g.lock);
    for (int i = 0; i < NBUCKETS && k < 4; i++)
        for (trec *r = g.b[i]; r && k < 4; r = r->next)
            if (r->state == S_UNTREATABLE && now_ms >= r->retry_at) {
                if (arms_of(r->cls)) {
                    trial(r);
                    news_of(&nw[k++], r, "the recheck");
                } else {
                    untreatable(r, now_ms);
                    news_of(&nw[k++], r, "still no arm for the class");
                }
            }
    plat_mutex_unlock(&g.lock);
    for (size_t i = 0; i < k; i++)
        tell(&nw[i]);
}

/* ---- ctl --------------------------------------------------------------------------------- */

void xtreat_status(jw *w)
{
    size_t n[5] = {0};
    if (!g.mode)
        return;
    plat_mutex_lock(&g.lock);
    for (int i = 0; i < NBUCKETS; i++)
        for (trec *r = g.b[i]; r; r = r->next)
            n[r->state]++;
    jw_key(w, "treat");
    jw_obj(w);
    jw_kstr(w, "mode", g.mode == XTR_PROPOSE ? "propose" : "apply");
    jw_kuint(w, "arms", NARMS);
    jw_kuint(w, "proposed", n[S_PROPOSED]);
    jw_kuint(w, "trial", n[S_TRIAL]);
    jw_kuint(w, "treat", n[S_TREAT]);
    jw_kuint(w, "untreatable", n[S_UNTREATABLE]);
    jw_obj_end(w);
    plat_mutex_unlock(&g.lock);
}

void xtreat_keys(jw *w, size_t max)
{
    size_t k = 0;
    if (!g.mode)
        return;
    plat_mutex_lock(&g.lock);
    jw_key(w, "treat");
    jw_arr(w);
    for (int i = 0; i < NBUCKETS && k < max; i++)
        for (trec *r = g.b[i]; r && k < max; r = r->next) {
            if (!r->state)
                continue;
            k++;
            jw_obj(w);
            jw_kstr(w, "key", r->name);
            jw_kstr(w, "level", xdet_level_name(r->level));
            jw_kstr(w, "state", state_name[r->state]);
            jw_kstr(w, "class", xdet_class_name(r->cls));
            if (r->state == S_TREAT) {
                jw_kint(w, "arm", r->treat + 1);
                jw_kstr(w, "strategy", portfolio[r->treat].text);
            }
            jw_key(w, "arms");
            jw_arr(w);
            for (size_t a = 0; a < NARMS; a++)
                if (arm_of(r, a)) {
                    jw_obj(w);
                    jw_kint(w, "arm", (int64_t)a + 1);
                    jw_kuint(w, "tries", r->tries[a]);
                    jw_kuint(w, "ok", r->succ[a]);
                    jw_obj_end(w);
                }
            jw_arr_end(w);
            jw_obj_end(w);
        }
    jw_arr_end(w);
    plat_mutex_unlock(&g.lock);
}

void xtreat_proposals(jw *w)
{
    if (!g.mode)
        return;
    plat_mutex_lock(&g.lock);
    for (int i = 0; i < NBUCKETS; i++)
        for (trec *r = g.b[i]; r; r = r->next)
            if (r->state == S_PROPOSED) {
                jw_obj(w);
                jw_kuint(w, "id", r->prop_id);
                jw_kstr(w, "key", r->name);
                jw_kstr(w, "kind", "treat");
                jw_kstr(w, "class", xdet_class_name(r->cls));
                jw_kuint(w, "arms", arms_of(r->cls));
                jw_obj_end(w);
            }
    plat_mutex_unlock(&g.lock);
}

int xtreat_decide(uint64_t id, int approve, jw *w)
{
    trec *found = NULL;
    tnews nw;
    if (!g.mode)
        return 0;
    memset(&nw, 0, sizeof(nw));
    plat_mutex_lock(&g.lock);
    for (int i = 0; i < NBUCKETS && !found; i++)
        for (trec *r = g.b[i]; r; r = r->next)
            if (r->state == S_PROPOSED && r->prop_id == id) {
                found = r;
                break;
            }
    if (found) {
        found->prop_id = 0;
        if (approve) {
            trial(found);
            news_of(&nw, found, "approved");
        } else {
            /* refused: the key stays as it is; impaired, untreated */
            set_state(found, S_UNTREATABLE);
            found->backoff = RETRY_MAX + 1;
            found->retry_at = UINT64_MAX;
            news_of(&nw, found, "refused");
            nw.retry_s = 0;
        }
        if (w) {
            jw_kstr(w, "key", found->name);
            jw_kstr(w, "state", state_name[found->state]);
        }
    }
    plat_mutex_unlock(&g.lock);
    tell(&nw);
    return found != NULL;
}
