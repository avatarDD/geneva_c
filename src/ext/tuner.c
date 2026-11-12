/*
 * The tuner (tuner.h): zapret2's circular with its detectors
 * (lua/zapret-auto.lua: standard_hostkey, automate_failure_counter,
 * standard_failure_detector, standard_success_detector, circular).
 */
#include "tuner.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "autolist.h"
#include "json.h"
#include "l7.h"
#include "log.h"
#include "plat.h"
#include "rng.h"

#ifdef _WIN32
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#endif


struct xtune {
    char **text; /* the arms as written */
    strategy **arm;
    size_t n;
    int set; /* --ext-tune given */
    int fails, time_s, final; /* final: 1-based, 0 none */
    char *key;                /* the keys' table */
    int nld, reqhost;
    int64_t maxseq, inseq, retrans, udp_out, udp_in;
    int no_rst, no_http_redirect, reset;
    int ts;          /* the selector: rr (0) or ts (1) */
    int propose;     /* changes wait for ext_approve */
    int rr_args;     /* fails, time or final given */
    double gamma;    /* ts: the discount of older outcomes */
    double pbest;    /* ts: P(best) that settles the key */
    int min_succ;    /* ts: ... with at least this many successes */
};

/* ---- building ------------------------------------------------------------------ */

static xtune *tnew(xtune **t)
{
    if (!*t) {
        *t = xcalloc(1, sizeof(**t));
        (*t)->fails = 3;
        (*t)->time_s = 60;
        (*t)->maxseq = 32768;
        (*t)->inseq = 4096;
        (*t)->retrans = 3;
        (*t)->udp_out = 4;
        (*t)->udp_in = 1;
        (*t)->gamma = 0.98;
        (*t)->pbest = 0.95;
        (*t)->min_succ = 5;
    }
    return *t;
}

void xtune_add_arm(xtune **t, const char *text)
{
    xtune *x = tnew(t);
    x->text = xrealloc(x->text, (x->n + 1) * sizeof(*x->text));
    x->text[x->n++] = xstrdup(text);
}

static int num(const char *k, const char *v, int64_t lo, int64_t hi, int64_t *out, sbuf *err)
{
    char *end;
    long long n;
    if (!v || !*v) {
        sb_printf(err, "--ext-tune: %s needs a number", k);
        return -1;
    }
    n = strtoll(v, &end, 10);
    if (*end || n < lo || n > hi) {
        sb_printf(err, "--ext-tune: %s=%s out of range [%lld, %lld]", k, v, (long long)lo, (long long)hi);
        return -1;
    }
    *out = n;
    return 0;
}

static int numf(const char *k, const char *v, double lo, double hi, double *out, sbuf *err)
{
    char *end;
    double n;
    if (!v || !*v) {
        sb_printf(err, "--ext-tune: %s needs a number", k);
        return -1;
    }
    n = strtod(v, &end);
    if (*end || !(n >= lo && n <= hi)) {
        sb_printf(err, "--ext-tune: %s=%s out of range [%g, %g]", k, v, lo, hi);
        return -1;
    }
    *out = n;
    return 0;
}

int xtune_set(xtune **t, const char *args, sbuf *err)
{
    xtune *x = tnew(t);
    char *s = xstrdup(args), *tok, *next;
    int rc = 0;
    if (x->set) {
        sb_puts(err, "--ext-tune is given once per profile");
        free(s);
        return -1;
    }
    x->set = 1;
    next = strchr(s, ':');
    if (next)
        *next++ = 0;
    x->ts = !strcmp(s, "ts");
    if (strcmp(s, "rr") && !x->ts) {
        sb_printf(err, "--ext-tune: unknown selector \"%s\" (rr, ts)", s);
        free(s);
        return -1;
    }
    for (tok = next; tok && !rc; tok = next) {
        char *v;
        int64_t n;
        double d;
        next = strchr(tok, ':');
        if (next)
            *next++ = 0;
        v = strchr(tok, '=');
        if (v)
            *v++ = 0;
        if (!*tok)
            continue;
#define NUM(name, lo, hi, field)                                                                                   \
    if (!strcmp(tok, name)) {                                                                                      \
        if ((rc = num(name, v, lo, hi, &n, err)) == 0)                                                             \
            field = n;                                                                                             \
        continue;                                                                                                  \
    }
#define FLAG(name, field)                                                                                          \
    if (!strcmp(tok, name)) {                                                                                      \
        if (v) {                                                                                                   \
            sb_printf(err, "--ext-tune: %s takes no value", name);                                                 \
            rc = -1;                                                                                               \
        }                                                                                                          \
        field = 1;                                                                                                 \
        continue;                                                                                                  \
    }
#define NUMF(name, lo, hi, field)                                                                                  \
    if (!strcmp(tok, name)) {                                                                                      \
        if ((rc = numf(name, v, lo, hi, &d, err)) == 0)                                                            \
            field = d;                                                                                             \
        continue;                                                                                                  \
    }
        if (!strcmp(tok, "fails") || !strcmp(tok, "time") || !strcmp(tok, "final"))
            x->rr_args = 1;
        NUM("fails", 1, 1000, x->fails)
        NUM("time", 1, 86400 * 30, x->time_s)
        NUM("final", 1, XT_MAX_ARMS, x->final)
        NUMF("gamma", 0.5, 1, x->gamma)
        NUMF("p", 0.5, 1, x->pbest)
        NUM("min_succ", 0, 1000000, x->min_succ)
        FLAG("propose", x->propose)
        NUM("nld", 0, 127, x->nld)
        NUM("maxseq", 0, 0x7fffffff, x->maxseq)
        NUM("inseq", 0, 0x7fffffff, x->inseq)
        NUM("retrans", 0, 1000, x->retrans)
        NUM("udp_out", 0, 1000000, x->udp_out)
        NUM("udp_in", 0, 1000000, x->udp_in)
        FLAG("reqhost", x->reqhost)
        FLAG("no_rst", x->no_rst)
        FLAG("no_http_redirect", x->no_http_redirect)
        FLAG("reset", x->reset)
#undef NUM
#undef NUMF
#undef FLAG
        if (!strcmp(tok, "key")) {
            if (!v || !*v || strlen(v) > 64 || strpbrk(v, "/\"\\")) {
                sb_puts(err, "--ext-tune: key needs a name (up to 64 characters, no /, \" or \\)");
                rc = -1;
            } else {
                free(x->key);
                x->key = xstrdup(v);
            }
            continue;
        }
        sb_printf(err, "--ext-tune: unknown argument \"%s\"", tok);
        rc = -1;
    }
    free(s);
    if (!rc && x->ts && x->rr_args) {
        sb_puts(err, "--ext-tune: fails, time and final are rr's (ts weighs every outcome)");
        rc = -1;
    }
    return rc;
}

void xtune_import(xtune **to, const xtune *from)
{
    xtune *x;
    if (!from || *to)
        return; /* the profile's own arms and arguments stay */
    x = tnew(to);
    *x = *from;
    x->text = xcalloc(from->n ? from->n : 1, sizeof(*x->text));
    for (size_t i = 0; i < from->n; i++)
        x->text[i] = xstrdup(from->text[i]);
    x->arm = NULL; /* parsed by xtune_finish */
    x->set = 0;    /* the profile's own --ext-tune may follow */
    x->key = from->key ? xstrdup(from->key) : NULL;
}

int xtune_finish(xtune *t, int prof, sbuf *err)
{
    if (!t)
        return 0;
    if (!t->n) {
        sb_puts(err, "--ext-tune needs arms (--ext-arm STRATEGY, one per arm)");
        return -1;
    }
    if (t->n > XT_MAX_ARMS) {
        sb_printf(err, "more than %d arms", XT_MAX_ARMS);
        return -1;
    }
    if (t->final > (int)t->n) {
        sb_printf(err, "--ext-tune: final=%d, but there are %zu arms", t->final, t->n);
        return -1;
    }
    if (!t->key) {
        char k[16];
        snprintf(k, sizeof(k), "p%d", prof);
        t->key = xstrdup(k);
    }
    if (!t->arm) {
        t->arm = xcalloc(t->n, sizeof(*t->arm));
        for (size_t i = 0; i < t->n; i++) {
            sbuf e;
            sb_init(&e);
            t->arm[i] = strategy_parse(t->text[i], &e);
            if (!t->arm[i]) {
                sb_printf(err, "--ext-arm %zu: %s", i + 1, e.data);
                sb_free(&e);
                return -1;
            }
            sb_free(&e);
        }
    }
    return 0;
}

void xtune_free(xtune *t)
{
    if (!t)
        return;
    for (size_t i = 0; i < t->n; i++) {
        free(t->text[i]);
        if (t->arm)
            strategy_free(t->arm[i]);
    }
    free(t->text);
    free(t->arm);
    free(t->key);
    free(t);
}

size_t xtune_arms(const xtune *t) { return t ? t->n : 0; }

strategy *xtune_arm(const xtune *t, size_t i) { return t && t->arm && i < t->n ? t->arm[i] : NULL; }

/* ---- the keys ------------------------------------------------------------------ */

/* zapret2's autostate[key][hostkey]: the arm (nstrategy) and the count */
typedef struct rec {
    struct rec *next;
    char *name; /* "TABLE/HOSTKEY" */
    int arm;    /* 1-based: rr's current one; ts with propose: the approved one */
    int counter; /* 0: none (nil) */
    uint64_t tlast; /* failure_time_last, seconds (0: none) */
    /* ts: discounted successes and failures per arm, Beta(1 + A, 1 + B) */
    double *A, *B;
    int na;
    int treat;         /* ts: the arm the key settled on (1-based), 0: exploring */
    uint64_t rejected; /* propose: the arms refused for the key (bit arm - 1) */
    int prop, prop_from, prop_arms; /* propose: a pending change (prop 0: none) */
    uint64_t prop_id;
} rec;

#define NBUCKETS 4096

static struct {
    int on;
    plat_mutex_t lock;
    rec *b[NBUCKETS];
    size_t n;
    char *state; /* --ext-state */
    int dirty;
    uint64_t t_saved;
    uint64_t rotations;
    uint64_t next_id; /* the proposals' ids */
} g;

static uint32_t hash32(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++)
        h = (h ^ (uint8_t)*s) * 16777619u;
    return h;
}

static unsigned hash(const char *s) { return hash32(s) % NBUCKETS; }

/* ts: room for n arms */
static void ts_room(rec *r, int n)
{
    if (r->na >= n)
        return;
    r->A = xrealloc(r->A, (size_t)n * sizeof(*r->A));
    r->B = xrealloc(r->B, (size_t)n * sizeof(*r->B));
    for (int i = r->na; i < n; i++)
        r->A[i] = r->B[i] = 0;
    r->na = n;
}

static rec *rec_get(const char *name, int create)
{
    unsigned h = hash(name);
    rec *r;
    for (r = g.b[h]; r; r = r->next)
        if (!strcmp(r->name, name))
            return r;
    if (!create || g.n >= XT_MAX_KEYS)
        return NULL;
    r = xcalloc(1, sizeof(*r));
    r->name = xstrdup(name);
    r->arm = 1;
    r->next = g.b[h];
    g.b[h] = r;
    g.n++;
    return r;
}

static void recs_free(void)
{
    for (int i = 0; i < NBUCKETS; i++) {
        rec *r = g.b[i], *n;
        for (; r; r = n) {
            n = r->next;
            free(r->name);
            free(r->A);
            free(r->B);
            free(r);
        }
        g.b[i] = NULL;
    }
    g.n = 0;
}

static void lock(void)
{
    if (g.on)
        plat_mutex_lock(&g.lock);
}

static void unlock(void)
{
    if (g.on)
        plat_mutex_unlock(&g.lock);
}

void xtune_reset(void)
{
    lock();
    recs_free();
    g.rotations = 0;
    unlock();
}

/* ---- the state file -------------------------------------------------------------- */

static void load(const char *text)
{
    const char *line = text;
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t l = end ? (size_t)(end - line) : strlen(line);
        char *s = xstrndup(line, l);
        const char *e = NULL;
        json_val *v = json_parse(s, &e);
        if (v) {
            const char *k = json_get_str(v, "key", NULL);
            int64_t arm = json_get_int(v, "arm", 0), treat = json_get_int(v, "treat", 0);
            const json_val *a = json_get(v, "a"), *b = json_get(v, "b");
            rec *r;
            if (k && arm >= 1 && arm <= XT_MAX_ARMS && strchr(k, '/') && (r = rec_get(k, 1))) {
                const json_val *rj = json_get(v, "rejected");
                r->arm = (int)arm;
                for (size_t i = 0; rj && rj->type == JSON_ARR && i < rj->n; i++)
                    if (rj->items[i]->type == JSON_NUM && rj->items[i]->num >= 1 && rj->items[i]->num <= XT_MAX_ARMS)
                        r->rejected |= 1ULL << ((int)rj->items[i]->num - 1);
                if (a && b && a->type == JSON_ARR && b->type == JSON_ARR && a->n == b->n && a->n &&
                    a->n <= XT_MAX_ARMS) {
                    ts_room(r, (int)a->n);
                    for (size_t i = 0; i < a->n; i++) {
                        double x = a->items[i]->num, y = b->items[i]->num;
                        r->A[i] = a->items[i]->type == JSON_NUM && x >= 0 && x < 1e6 ? x : 0;
                        r->B[i] = b->items[i]->type == JSON_NUM && y >= 0 && y < 1e6 ? y : 0;
                    }
                    if (treat >= 1 && treat <= (int64_t)a->n)
                        r->treat = (int)treat;
                }
            }
            json_free(v);
        }
        free(s);
        line = end ? end + 1 : NULL;
    }
}

/* the workers set dirty under the lock */
static int is_dirty(void)
{
    int d;
    lock();
    d = g.dirty;
    unlock();
    return d;
}

static void save(void)
{
    sbuf s;
    if (!g.state)
        return;
    sb_init(&s);
    lock();
    for (int i = 0; i < NBUCKETS; i++)
        for (rec *r = g.b[i]; r; r = r->next) {
            jw w;
            jw_init(&w, &s);
            jw_obj(&w);
            jw_kstr(&w, "key", r->name);
            jw_kint(&w, "arm", r->arm);
            if (r->na) {
                jw_key(&w, "a");
                jw_arr(&w);
                for (int k = 0; k < r->na; k++)
                    jw_dbl(&w, r->A[k]);
                jw_arr_end(&w);
                jw_key(&w, "b");
                jw_arr(&w);
                for (int k = 0; k < r->na; k++)
                    jw_dbl(&w, r->B[k]);
                jw_arr_end(&w);
                if (r->treat)
                    jw_kint(&w, "treat", r->treat);
            }
            if (r->rejected) {
                jw_key(&w, "rejected");
                jw_arr(&w);
                for (int k = 0; k < XT_MAX_ARMS; k++)
                    if (r->rejected >> k & 1)
                        jw_int(&w, k + 1);
                jw_arr_end(&w);
            }
            jw_obj_end(&w);
            sb_putc(&s, '\n');
        }
    g.dirty = 0;
    unlock();
    if (plat_write_atomic(g.state, s.data ? s.data : "", s.len) < 0)
        LOGW("tuner", "cannot write %s", g.state);
    sb_free(&s);
}

int xtune_start(const char *state_file, sbuf *err)
{
    xtune_stop();
    plat_mutex_init(&g.lock);
    g.on = 1;
    if (state_file) {
        size_t len;
        char *t;
        g.state = xstrdup(state_file);
        t = read_file(state_file, &len);
        if (t) {
            load(t);
            free(t);
            LOGI("tuner", "%zu key(s) from %s", g.n, state_file);
        } else {
            FILE *f = fopen(state_file, "ab"); /* can it be written? */
            if (!f) {
                sb_printf(err, "--ext-state %s: cannot write it", state_file);
                xtune_stop();
                return -1;
            }
            fclose(f);
        }
    }
    return 0;
}

void xtune_stop(void)
{
    if (!g.on)
        return;
    if (g.state && is_dirty())
        save();
    recs_free();
    free(g.state);
    plat_mutex_destroy(&g.lock);
    memset(&g, 0, sizeof(g));
}

void xtune_save(void)
{
    if (g.on && g.state && is_dirty())
        save();
}

void xtune_tick(uint64_t now_ms)
{
    if (!g.on || !g.state || (g.t_saved && now_ms - g.t_saved < 10000) || !is_dirty())
        return;
    g.t_saved = now_ms;
    save();
}

/* ---- circular --------------------------------------------------------------------- */

/* dissect_nld: the domain from its level-th level (NULL: it has fewer) */
static const char *nld(const char *d, int level)
{
    int n = 1;
    for (size_t pos = strlen(d); pos > 0; pos--)
        if (d[pos - 1] == '.') {
            if (n == level)
                return d + pos;
            n++;
        }
    return n == level ? d : NULL;
}

int xtune_hostkey(const xtune *t, const ct_flow *f, char *out, size_t cap)
{
    const char *h = f->chost;
    if (h && *h) {
        if (t->nld > 0 && !f->chost_ip) {
            const char *c = nld(h, t->nld);
            if (c)
                h = c;
        }
        snprintf(out, cap, "%s", h);
        return 1;
    }
    if (t->reqhost)
        return 0;
    return inet_ntop(f->ver == 6 ? AF_INET6 : AF_INET, f->srv, out, (socklen_t)cap) != NULL;
}

static int full_name(const xtune *t, const ct_flow *f, char *out, size_t cap)
{
    char hk[300];
    if (!xtune_hostkey(t, f, hk, sizeof(hk)))
        return 0;
    snprintf(out, cap, "%s/%s", t->key, hk);
    return 1;
}

/* the direction's own side and the other one */
static const ct_side *direct(const xtune_pkt *k) { return k->reverse ? &k->f->server : &k->f->client; }
static const ct_side *other(const xtune_pkt *k) { return k->reverse ? &k->f->client : &k->f->server; }

/* standard_success_detector */
static int success(const xtune *t, const xtune_pkt *k)
{
    const gpkt *p = k->p;
    if (p->l4 == LAYER_TCP) {
        const ct_side *s = direct(k);
        int64_t seq = (int64_t)(uint32_t)(s->seq_last - s->seq0);
        if (!k->reverse)
            return t->maxseq > 0 && seq > t->maxseq;
        return t->inseq > 0 && seq > t->inseq;
    }
    if (p->l4 == LAYER_UDP && k->reverse)
        return t->udp_out > 0 && (int64_t)direct(k)->pcounter > t->udp_in;
    return 0;
}

/* standard_failure_detector */
static int failure(const xtune *t, const xtune_pkt *k)
{
    const gpkt *p = k->p;
    ct_flow *f = k->f;
    if (p->l4 == LAYER_TCP) {
        const ct_side *s = direct(k);
        int64_t seq = (int64_t)(uint32_t)(s->seq_last - s->seq0);
        if (!k->reverse) {
            int trig;
            if (!p->payload_len || !t->retrans || t->maxseq <= 0 || seq > t->maxseq || f->xt_retrans >= t->retrans)
                return 0;
            if (!ct_is_retrans(s))
                return 0;
            f->xt_retrans++;
            LOGD("tuner", "retransmission %d/%lld", (int)f->xt_retrans, (long long)t->retrans);
            trig = f->xt_retrans >= t->retrans;
            if (trig && t->reset && k->send) {
                uint8_t rst[60];
                size_t n = xah_rst(p, f, rst);
                if (n) {
                    LOGD("tuner", "sending RST to retransmitter");
                    k->send(k->ud, rst, n);
                }
            }
            return trig;
        }
        if (!t->no_rst && t->inseq > 0 && (p->tcpflags & 0x04) && seq >= 1) {
            LOGD("tuner", "incoming RST s%lld %s s%lld", (long long)seq, seq <= t->inseq ? "in range" : "beyond",
                 (long long)t->inseq);
            return seq <= t->inseq;
        }
        if (!t->no_http_redirect && k->http_reply && f->chost && *f->chost)
            return l7_http_dpi_redirect(p->payload, p->payload_len, f->chost);
        return 0;
    }
    if (p->l4 == LAYER_UDP && !k->reverse && t->udp_out > 0)
        return (int64_t)direct(k)->pcounter >= t->udp_out && (int64_t)other(k)->pcounter <= t->udp_in;
    return 0;
}

/* ---- ts: Thompson sampling ---------------------------------------------------------- */

#define XT_PI 3.14159265358979323846
#define XT_DRAWS 200 /* the Monte Carlo draws of P(best) */

static double gauss(void)
{
    double u1 = 1.0 - rng_real(), u2 = rng_real();
    return sqrt(-2.0 * log(u1)) * cos(2.0 * XT_PI * u2);
}

/* Gamma(a, 1) for a >= 1 (Marsaglia and Tsang) */
static double gamma_ge1(double a)
{
    double d = a - 1.0 / 3.0, c = 1.0 / sqrt(9.0 * d);
    for (;;) {
        double x, v, u;
        do {
            x = gauss();
            v = 1.0 + c * x;
        } while (v <= 0);
        v = v * v * v;
        u = 1.0 - rng_real();
        if (u < 1.0 - 0.0331 * x * x * x * x || log(u) < 0.5 * x * x + d * (1.0 - v + log(v)))
            return d * v;
    }
}

static double beta_draw(double a, double b)
{
    double x = gamma_ge1(a), y = gamma_ge1(b);
    return x / (x + y);
}

static int allowed(const rec *r, int arm, int except) { return arm != except && !(r->rejected >> (arm - 1) & 1); }

/* One Thompson draw over the arms of r but except (1-based); 0: none left */
static int ts_pick(const xtune *t, rec *r, int except)
{
    double best = -1;
    int arm = 0;
    ts_room(r, (int)t->n);
    for (int i = 1; i <= (int)t->n; i++) {
        double x;
        if (!allowed(r, i, except))
            continue;
        x = beta_draw(1.0 + r->A[i - 1], 1.0 + r->B[i - 1]);
        if (x > best)
            best = x, arm = i;
    }
    return arm;
}

/* P(each arm is the best one), by XT_DRAWS draws: the most likely arm
 * and its probability */
static int ts_best(const xtune *t, rec *r, double *p)
{
    int wins[XT_MAX_ARMS] = {0}, top = 0;
    for (int k = 0; k < XT_DRAWS; k++) {
        int a = ts_pick(t, r, 0);
        if (a)
            wins[a - 1]++;
    }
    for (int i = 1; i < (int)t->n; i++)
        if (wins[i] > wins[top])
            top = i;
    *p = (double)wins[top] / XT_DRAWS;
    return top + 1;
}

/* what changed under the lock, told after it */
typedef struct {
    int arm;      /* the key's arm changed to this (ext_arm) */
    uint64_t pid; /* a proposal was made */
    int pfrom, pto;
    int tuned;    /* 1: settled on tuned_arm, 2: exploring again */
    int tuned_arm;
    double p;
} news;

/* An outcome of arm (1-based) on key r: older ones weigh gamma times less */
static void ts_outcome(const xtune *t, rec *r, int arm, int ok, news *nw)
{
    double p;
    int best;
    ts_room(r, (int)t->n);
    for (int i = 0; i < r->na; i++) {
        r->A[i] *= t->gamma;
        r->B[i] *= t->gamma;
    }
    if (ok)
        r->A[arm - 1] += 1;
    else
        r->B[arm - 1] += 1;
    g.dirty = 1;
    if (t->propose)
        return; /* only the approved arm runs: nothing to settle */
    best = ts_best(t, r, &p);
    if (!r->treat && p >= t->pbest && r->A[best - 1] >= t->min_succ) {
        r->treat = best;
        nw->tuned = 1, nw->tuned_arm = best, nw->p = p;
    } else if (r->treat && (best != r->treat || p < 0.5)) {
        nw->tuned = 2, nw->tuned_arm = r->treat, nw->p = p;
        r->treat = 0;
    }
}

static void propose(rec *r, int to, size_t arms, news *nw)
{
    if (r->prop || !to || to == r->arm)
        return; /* one at a time; nothing else to try */
    r->prop = to;
    r->prop_from = r->arm;
    r->prop_arms = (int)arms;
    r->prop_id = ++g.next_id;
    nw->pid = r->prop_id, nw->pfrom = r->arm, nw->pto = to;
}

/* after the lock: the log and the event take their own */
static void arm_event(const char *name, int arm, size_t arms, int final)
{
    LOGI("tuner", "%s: arm %d of %zu%s", name, arm, arms, final ? " (final)" : "");
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "ext_arm");
        jw_kstr(&e.w, "key", name);
        jw_kint(&e.w, "arm", arm);
        jw_kuint(&e.w, "arms", arms);
        jw_kbool(&e.w, "final", final);
        ev_emit(&e);
    }
}

static void tell(const xtune *t, const char *name, const news *nw)
{
    if (nw->arm)
        arm_event(name, nw->arm, t->n, nw->arm == t->final);
    if (nw->pid) {
        LOGI("tuner", "%s: proposal %llu: arm %d instead of %d", name, (unsigned long long)nw->pid, nw->pto,
             nw->pfrom);
        if (ev_enabled()) {
            ev_t e;
            ev_begin(&e, "ext_proposal");
            jw_kuint(&e.w, "id", nw->pid);
            jw_kstr(&e.w, "key", name);
            jw_kint(&e.w, "from", nw->pfrom);
            jw_kint(&e.w, "to", nw->pto);
            jw_kuint(&e.w, "arms", t->n);
            jw_kstr(&e.w, "selector", t->ts ? "ts" : "rr");
            ev_emit(&e);
        }
    }
    if (nw->tuned) {
        LOGI("tuner", "%s: %s arm %d (P(best) %.2f)", name, nw->tuned == 1 ? "settled on" : "explores again, was",
             nw->tuned_arm, nw->p);
        if (ev_enabled()) {
            ev_t e;
            ev_begin(&e, "ext_tuned");
            jw_kstr(&e.w, "key", name);
            jw_kint(&e.w, "arm", nw->tuned == 1 ? nw->tuned_arm : 0);
            jw_kdbl(&e.w, "p", nw->p);
            ev_emit(&e);
        }
    }
}

/* the connection's outcome by the detectors: 1 success, -1 failure (a
 * new one: one per connection), 0 none yet or counted before */
static int outcome(const xtune *t, const xtune_pkt *k, const char *name)
{
    ct_flow *f = k->f;
    if (f->xt_nocheck)
        return 0;
    if (success(t, k)) {
        f->xt_nocheck = 1;
        LOGD("tuner", "%s: success detected", name);
        return 1;
    }
    if (failure(t, k)) {
        f->xt_nocheck = 1;
        LOGD("tuner", "%s: failure detected", name);
        if (!f->xt_failure) {
            f->xt_failure = 1;
            return -1;
        }
        LOGD("tuner", "%s: duplicate failure in the same connection, not counted", name);
    }
    return 0;
}

/* circular: rr's step under the lock */
static void rr_step(const xtune *t, rec *r, const xtune_pkt *k, const char *name, news *nw)
{
    int o;
    if (t->final == r->arm)
        return;
    o = outcome(t, k, name);
    if (o > 0) {
        r->counter = 0;
    } else if (o < 0) {
        /* automate_failure_counter */
        uint64_t tnow = k->now_ms / 1000;
        if (!r->tlast)
            r->tlast = tnow;
        if (r->counter && tnow > r->tlast + (uint64_t)t->time_s)
            r->counter = 0;
        r->counter++;
        r->tlast = tnow;
        LOGD("tuner", "%s: failure counter %d/%d", name, r->counter, t->fails);
        if (r->counter >= t->fails) {
            int next = r->arm;
            r->counter = 0;
            /* the next arm; with propose, past the refused ones */
            for (size_t i = 0; i < t->n; i++) {
                next = next % (int)t->n + 1;
                if (!t->propose || allowed(r, next, 0))
                    break;
            }
            if (t->propose) {
                propose(r, next, t->n, nw);
            } else {
                r->arm = next;
                g.rotations++;
                g.dirty = 1;
                nw->arm = next;
            }
        }
    }
}

/* ts's step under the lock: the connection's arm (1-based) */
static int ts_step(const xtune *t, rec *r, const xtune_pkt *k, const char *name, uint32_t kh, news *nw)
{
    ct_flow *f = k->f;
    int o, arm;
    if (t->propose) {
        f->xt_arm = (uint8_t)r->arm;
    } else if (!f->xt_arm || f->xt_khash != kh) {
        /* the connection's arm, once per key: settled, or a draw */
        f->xt_arm = (uint8_t)(r->treat ? r->treat : ts_pick(t, r, 0));
        if (!f->xt_arm)
            f->xt_arm = 1;
        LOGD("tuner", "%s: the connection runs arm %d", name, f->xt_arm);
    }
    f->xt_khash = kh;
    arm = f->xt_arm;
    o = outcome(t, k, name);
    if (o) {
        ts_outcome(t, r, arm, o > 0, nw);
        if (o < 0 && t->propose && arm == r->arm)
            propose(r, ts_pick(t, r, arm), t->n, nw);
    }
    return arm;
}

int xtune_packet(xtune *t, const xtune_pkt *k)
{
    char name[400];
    ct_flow *f = k->f;
    rec *r;
    int arm;
    news nw;
    if (!t || !f || !full_name(t, f, name, sizeof(name)))
        return -1;
    memset(&nw, 0, sizeof(nw));
    lock();
    r = rec_get(name, 1);
    if (!r) {
        unlock();
        return 0; /* the table is full: arm 1, nothing counted */
    }
    if (r->arm > (int)t->n)
        r->arm = 1; /* from a state file of more arms */
    if (r->treat > (int)t->n)
        r->treat = 0;
    if (t->ts) {
        arm = ts_step(t, r, k, name, hash32(name), &nw);
    } else {
        rr_step(t, r, k, name, &nw);
        arm = r->arm;
    }
    unlock();
    tell(t, name, &nw);
    return arm - 1;
}

int xtune_current(xtune *t, const ct_flow *f)
{
    char name[400];
    rec *r;
    int arm = 0;
    if (!t || !f || !full_name(t, f, name, sizeof(name)))
        return -1;
    if (t->ts && !t->propose && f->xt_arm && f->xt_khash == hash32(name) && f->xt_arm <= t->n)
        return f->xt_arm - 1; /* the connection keeps its draw */
    lock();
    r = rec_get(name, 0);
    if (r && t->ts && !t->propose)
        arm = r->treat && r->treat <= (int)t->n ? r->treat - 1 : 0;
    else if (r && r->arm <= (int)t->n)
        arm = r->arm - 1;
    unlock();
    return arm;
}

/* ---- ctl --------------------------------------------------------------------------- */

void xtune_status(jw *w)
{
    size_t props = 0, treated = 0;
    if (!g.on)
        return;
    lock();
    for (int i = 0; i < NBUCKETS; i++)
        for (rec *r = g.b[i]; r; r = r->next) {
            props += r->prop != 0;
            treated += r->treat != 0;
        }
    jw_key(w, "tuner");
    jw_obj(w);
    jw_kuint(w, "keys", g.n);
    jw_kuint(w, "rotations", g.rotations);
    jw_kuint(w, "proposals", props);
    jw_kuint(w, "settled", treated);
    if (g.state)
        jw_kstr(w, "state", g.state);
    jw_obj_end(w);
    unlock();
}

void xtune_keys(jw *w, size_t max)
{
    size_t n = 0;
    if (!g.on)
        return;
    lock();
    jw_key(w, "tuner");
    jw_arr(w);
    for (int i = 0; i < NBUCKETS && n < max; i++)
        for (rec *r = g.b[i]; r && n < max; r = r->next, n++) {
            jw_obj(w);
            jw_kstr(w, "key", r->name);
            jw_kint(w, "arm", r->arm);
            jw_kint(w, "fails", r->counter);
            if (r->na) {
                jw_key(w, "mean"); /* ts: the posterior mean of each arm's success */
                jw_arr(w);
                for (int k = 0; k < r->na; k++)
                    jw_dbl(w, floor((1.0 + r->A[k]) / (2.0 + r->A[k] + r->B[k]) * 1000 + 0.5) / 1000);
                jw_arr_end(w);
                jw_kint(w, "settled", r->treat);
            }
            if (r->prop) {
                jw_key(w, "proposal");
                jw_obj(w);
                jw_kuint(w, "id", r->prop_id);
                jw_kint(w, "to", r->prop);
                jw_obj_end(w);
            }
            if (r->rejected) {
                jw_key(w, "rejected");
                jw_arr(w);
                for (int k = 0; k < XT_MAX_ARMS; k++)
                    if (r->rejected >> k & 1)
                        jw_int(w, k + 1);
                jw_arr_end(w);
            }
            jw_obj_end(w);
        }
    jw_arr_end(w);
    unlock();
}

static rec *by_id(uint64_t id)
{
    for (int i = 0; i < NBUCKETS; i++)
        for (rec *r = g.b[i]; r; r = r->next)
            if (r->prop && r->prop_id == id)
                return r;
    return NULL;
}

int xtune_control(const char *cmd, const json_val *req, jw *w, sbuf *err)
{
    int approve = !strcmp(cmd, "ext_approve");
    if (!strcmp(cmd, "ext_proposals")) {
        if (!w)
            return 1;
        jw_key(w, "proposals");
        jw_arr(w);
        if (g.on) {
            lock();
            for (int i = 0; i < NBUCKETS; i++)
                for (rec *r = g.b[i]; r; r = r->next)
                    if (r->prop) {
                        jw_obj(w);
                        jw_kuint(w, "id", r->prop_id);
                        jw_kstr(w, "key", r->name);
                        jw_kint(w, "from", r->prop_from);
                        jw_kint(w, "to", r->prop);
                        jw_kint(w, "arms", r->prop_arms);
                        jw_obj_end(w);
                    }
            unlock();
        }
        jw_arr_end(w);
        return 1;
    }
    if (approve || !strcmp(cmd, "ext_reject")) {
        /* "proposal": a number, or a string of one ("geneva ctl ext_approve
         * proposal=3"); "id" is the request's own */
        const char *ids = json_get_str(req, "proposal", NULL);
        int64_t id = ids ? strtoll(ids, NULL, 10) : json_get_int(req, "proposal", 0);
        char name[400];
        int to = 0, arms = 0;
        rec *r;
        if (!g.on) {
            sb_puts(err, "no tuner (--ext-arm)");
            return -1;
        }
        lock();
        r = id > 0 ? by_id((uint64_t)id) : NULL;
        if (r) {
            to = r->prop;
            arms = r->prop_arms;
            snprintf(name, sizeof(name), "%s", r->name);
            if (approve) {
                r->arm = to;
                r->counter = 0;
                g.rotations++;
            } else {
                r->rejected |= 1ULL << (to - 1);
            }
            r->prop = 0;
            g.dirty = 1;
        }
        unlock();
        if (!r) {
            sb_printf(err, "no proposal %lld (ext_proposals lists them)", (long long)id);
            return -1;
        }
        if (approve)
            arm_event(name, to, (size_t)arms, 0);
        else
            LOGI("tuner", "%s: arm %d refused", name, to);
        if (w) {
            jw_kstr(w, "key", name);
            jw_kint(w, approve ? "arm" : "refused", to);
        }
        return 1;
    }
    return 0;
}
