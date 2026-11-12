/*
 * The tuner (tuner.h): zapret2's circular with its detectors
 * (lua/zapret-auto.lua: standard_hostkey, automate_failure_counter,
 * standard_failure_detector, standard_success_detector, circular).
 */
#include "tuner.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "autolist.h"
#include "json.h"
#include "l7.h"
#include "log.h"
#include "plat.h"

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
    if (!strcmp(s, "ts")) {
        sb_puts(err, "--ext-tune ts is not there yet: rr");
        free(s);
        return -1;
    }
    if (strcmp(s, "rr")) {
        sb_printf(err, "--ext-tune: unknown selector \"%s\" (rr)", s);
        free(s);
        return -1;
    }
    for (tok = next; tok && !rc; tok = next) {
        char *v;
        int64_t n;
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
        NUM("fails", 1, 1000, x->fails)
        NUM("time", 1, 86400 * 30, x->time_s)
        NUM("final", 1, XT_MAX_ARMS, x->final)
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
    int arm;    /* 1-based */
    int counter; /* 0: none (nil) */
    uint64_t tlast; /* failure_time_last, seconds (0: none) */
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
} g;

static unsigned hash(const char *s)
{
    unsigned h = 2166136261u;
    for (; *s; s++)
        h = (h ^ (uint8_t)*s) * 16777619u;
    return h % NBUCKETS;
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
            int64_t arm = json_get_int(v, "arm", 0);
            rec *r;
            if (k && arm >= 1 && arm <= XT_MAX_ARMS && strchr(k, '/') && (r = rec_get(k, 1)))
                r->arm = (int)arm;
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

/* after the lock: the log and the event take their own */
static void rotated(const xtune *t, const char *name, int arm)
{
    LOGI("tuner", "%s: arm %d of %zu%s", name, arm, t->n, arm == t->final ? " (final)" : "");
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "ext_arm");
        jw_kstr(&e.w, "key", name);
        jw_kint(&e.w, "arm", arm);
        jw_kuint(&e.w, "arms", t->n);
        jw_kbool(&e.w, "final", arm == t->final);
        ev_emit(&e);
    }
}

int xtune_packet(xtune *t, const xtune_pkt *k)
{
    char name[400];
    ct_flow *f = k->f;
    rec *r;
    int arm, rot = 0;
    if (!t || !f || !full_name(t, f, name, sizeof(name)))
        return -1;
    lock();
    r = rec_get(name, 1);
    if (!r) {
        unlock();
        return 0; /* the table is full: arm 1, nothing counted */
    }
    if (r->arm > (int)t->n)
        r->arm = 1; /* from a state file of more arms */
    if (t->final != r->arm && !f->xt_nocheck) {
        if (success(t, k)) {
            f->xt_nocheck = 1;
            LOGD("tuner", "%s: success detected", name);
            r->counter = 0;
        } else if (failure(t, k)) {
            /* automate_failure_counter */
            uint64_t tnow = k->now_ms / 1000;
            f->xt_nocheck = 1;
            LOGD("tuner", "%s: failure detected", name);
            if (!f->xt_failure) {
                f->xt_failure = 1;
                if (!r->tlast)
                    r->tlast = tnow;
                if (r->counter && tnow > r->tlast + (uint64_t)t->time_s)
                    r->counter = 0;
                r->counter++;
                r->tlast = tnow;
                LOGD("tuner", "%s: failure counter %d/%d", name, r->counter, t->fails);
                if (r->counter >= t->fails) {
                    r->counter = 0;
                    r->arm = r->arm % (int)t->n + 1;
                    g.rotations++;
                    g.dirty = 1;
                    rot = 1;
                }
            }
        }
    }
    arm = r->arm - 1;
    unlock();
    if (rot)
        rotated(t, name, arm + 1);
    return arm;
}

int xtune_current(xtune *t, const ct_flow *f)
{
    char name[400];
    rec *r;
    int arm = 0;
    if (!t || !f || !full_name(t, f, name, sizeof(name)))
        return -1;
    lock();
    r = rec_get(name, 0);
    if (r && r->arm <= (int)t->n)
        arm = r->arm - 1;
    unlock();
    return arm;
}

/* ---- ctl --------------------------------------------------------------------------- */

void xtune_status(jw *w)
{
    if (!g.on)
        return;
    lock();
    jw_key(w, "tuner");
    jw_obj(w);
    jw_kuint(w, "keys", g.n);
    jw_kuint(w, "rotations", g.rotations);
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
            jw_obj_end(w);
        }
    jw_arr_end(w);
    unlock();
}
