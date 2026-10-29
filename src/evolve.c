#include "evolve.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "json.h"
#include "log.h"
#include "plat.h"
#include "rng.h"

#define MAX_MUTATION_TRIES 1000

void ga_opts_default(ga_opts *o)
{
    memset(o, 0, sizeof(*o));
    o->population = 250;
    o->generations = 50;
    o->elite_clones = 3;
    o->allowed_retries = 20;
    o->in_trees = 0;
    o->out_trees = 1;
    o->in_actions = 2;
    o->out_actions = 2;
    o->tournsize = 10;
    o->mutation_pb = 0.99;
    o->crossover_pb = 0.4;
    o->target = "";
    o->gen.disabled[ACT_SLEEP] = 1;
    o->gen.disabled[ACT_TRACE] = 1;
}

/* ---- hall of fame -------------------------------------------------------- */

static uint64_t str_hash(const char *s)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++)
        h = (h ^ (uint8_t)*s) * 1099511628211ull;
    return h;
}

void hof_init(hall_of_fame *h) { memset(h, 0, sizeof(*h)); }

void hof_free(hall_of_fame *h)
{
    for (size_t i = 0; i < h->n; i++) {
        free(h->v[i].str);
        free(h->v[i].fits);
    }
    free(h->v);
    free(h->idx);
    memset(h, 0, sizeof(*h));
}

static long hof_find(const hall_of_fame *h, const char *str)
{
    size_t k;
    if (!h->idx_cap)
        return -1;
    k = (size_t)str_hash(str) & (h->idx_cap - 1);
    while (h->idx[k]) {
        if (!strcmp(h->v[h->idx[k] - 1].str, str))
            return (long)(h->idx[k] - 1);
        k = (k + 1) & (h->idx_cap - 1);
    }
    return -1;
}

static void hof_reindex(hall_of_fame *h)
{
    free(h->idx);
    h->idx_cap = 64;
    while (h->idx_cap < h->n * 2 + 2)
        h->idx_cap *= 2;
    h->idx = xcalloc(h->idx_cap, sizeof(*h->idx));
    for (size_t i = 0; i < h->n; i++) {
        size_t k = (size_t)str_hash(h->v[i].str) & (h->idx_cap - 1);
        while (h->idx[k])
            k = (k + 1) & (h->idx_cap - 1);
        h->idx[k] = i + 1;
    }
}

void hof_add(hall_of_fame *h, const char *str, double fit)
{
    long i = hof_find(h, str);
    hof_entry *e;
    if (i < 0) {
        if (h->n == h->cap) {
            h->cap = h->cap ? h->cap * 2 : 64;
            h->v = xrealloc(h->v, h->cap * sizeof(*h->v));
        }
        e = &h->v[h->n++];
        memset(e, 0, sizeof(*e));
        e->str = xstrdup(str);
        if (h->n * 2 + 2 > h->idx_cap) {
            hof_reindex(h);
        } else {
            size_t k = (size_t)str_hash(str) & (h->idx_cap - 1);
            while (h->idx[k])
                k = (k + 1) & (h->idx_cap - 1);
            h->idx[k] = h->n;
        }
    } else {
        e = &h->v[i];
    }
    if (e->n == e->cap) {
        e->cap = e->cap ? e->cap * 2 : 4;
        e->fits = xrealloc(e->fits, e->cap * sizeof(*e->fits));
    }
    e->fits[e->n++] = fit;
}

const hof_entry *hof_get(const hall_of_fame *h, const char *str)
{
    long i = hof_find(h, str);
    return i >= 0 ? &h->v[i] : NULL;
}

static double hof_avg(const hof_entry *e)
{
    double s = 0;
    for (size_t i = 0; i < e->n; i++)
        s += e->fits[i];
    return e->n ? s / (double)e->n : 0;
}

static int hof_cmp_geneva(const void *pa, const void *pb)
{
    const hof_entry *a = *(const hof_entry *const *)pa, *b = *(const hof_entry *const *)pb;
    double x = hof_avg(a), y = hof_avg(b);
    if (a->n != b->n)
        return a->n < b->n ? -1 : 1;
    if (x != y)
        return x < y ? -1 : 1;
    return 0;
}

static int hof_cmp_best(const void *pa, const void *pb)
{
    const hof_entry *a = *(const hof_entry *const *)pa, *b = *(const hof_entry *const *)pb;
    double x = hof_avg(a), y = hof_avg(b);
    if (x != y)
        return x > y ? -1 : 1;
    if (a->n != b->n)
        return a->n > b->n ? -1 : 1;
    return strcmp(a->str, b->str);
}

static const hof_entry **hof_sorted(const hall_of_fame *h, int (*cmp)(const void *, const void *))
{
    const hof_entry **v = xmalloc((h->n + 1) * sizeof(*v));
    for (size_t i = 0; i < h->n; i++)
        v[i] = &h->v[i];
    qsort(v, h->n, sizeof(*v), cmp);
    return v;
}

void hof_format(const hall_of_fame *h, sbuf *out)
{
    const hof_entry **v = hof_sorted(h, hof_cmp_geneva);
    sb_puts(out, "Results: \n");
    for (size_t i = 0; i < h->n; i++) {
        sb_printf(out, "Avg. Fitness %g: %s (Evaluated %zu times: [", hof_avg(v[i]), v[i]->str, v[i]->n);
        for (size_t k = 0; k < v[i]->n; k++)
            sb_printf(out, "%s%g", k ? ", " : "", v[i]->fits[k]);
        sb_puts(out, "])\n");
    }
    free(v);
}

size_t hof_best(const hall_of_fame *h, const hof_entry **out, size_t max)
{
    const hof_entry **v = hof_sorted(h, hof_cmp_best);
    size_t n = h->n < max ? h->n : max;
    memcpy(out, v, n * sizeof(*out));
    free(v);
    return n;
}

/* ---- individuals --------------------------------------------------------- */

typedef struct {
    ga_ind *v;
    size_t n, cap;
} pop_t;

static void ind_free(ga_ind *i)
{
    strategy_free(i->s);
    free(i->str);
    memset(i, 0, sizeof(*i));
}

static void pop_clear(pop_t *p)
{
    for (size_t i = 0; i < p->n; i++)
        ind_free(&p->v[i]);
    p->n = 0;
}

static void pop_free(pop_t *p)
{
    pop_clear(p);
    free(p->v);
    memset(p, 0, sizeof(*p));
}

/* Takes ownership of s. Returns -1 (and frees s) if it is not canonical. */
static int pop_push(pop_t *p, strategy *s, double fit, int in_en, int out_en)
{
    char *str = NULL;
    if (strategy_canon(&s, &str) < 0) {
        strategy_free(s);
        return -1;
    }
    if (p->n == p->cap) {
        p->cap = p->cap ? p->cap * 2 : 64;
        p->v = xrealloc(p->v, p->cap * sizeof(*p->v));
    }
    p->v[p->n].s = s;
    p->v[p->n].str = str;
    p->v[p->n].fit = fit;
    p->v[p->n].in_en = in_en;
    p->v[p->n].out_en = out_en;
    p->n++;
    return 0;
}

static void pop_push_copy(pop_t *p, const ga_ind *src)
{
    strategy *c = strategy_copy(src->s);
    if (!c || pop_push(p, c, src->fit, src->in_en, src->out_en) < 0)
        LOGE("ga", "internal error: cannot copy %s", src->str); /* individuals are canonical */
}

static int pop_push_text(pop_t *p, const char *text, double fit, int in_en, int out_en, sbuf *err)
{
    strategy *s = strategy_parse(text, err);
    if (!s)
        return -1;
    if (pop_push(p, s, fit, in_en, out_en) < 0) {
        sb_printf(err, "strategy does not print back the same: %s", text);
        return -1;
    }
    return 0;
}

/* ---- initial population -------------------------------------------------- */

static int load_generation(pop_t *p, const char *path, sbuf *err)
{
    size_t len;
    char *text = read_file(path, &len), *line, *next;
    if (!text) {
        sb_printf(err, "cannot read %s", path);
        return -1;
    }
    for (line = text; line && *line; line = next) {
        char *end;
        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        end = line + strlen(line);
        while (end > line && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
            *--end = 0;
        if (!*line || *line == '#')
            continue;
        if (pop_push_text(p, line, -1000, 1, 1, err) < 0) {
            free(text);
            return -1;
        }
    }
    free(text);
    if (!p->n) {
        sb_printf(err, "no strategies in %s", path);
        return -1;
    }
    return 0;
}

static int initialize_population(ga_opts *o, pop_t *p, sbuf *err)
{
    int in_en = o->in_trees > 0, out_en = o->out_trees > 0;
    if (o->load_from)
        return load_generation(p, o->load_from, err);
    for (int i = 0; i < o->population; i++) {
        if (o->seed) {
            if (pop_push_text(p, o->seed, -1000, in_en, out_en, err) < 0)
                return -1;
            continue;
        }
        for (int tries = 0;; tries++) {
            strategy *s = strategy_random(&o->gen, o->in_trees, o->out_trees, o->in_actions, o->out_actions);
            if (pop_push(p, s, -1000, in_en, out_en) == 0)
                break;
            if (tries == 100) {
                sb_puts(err, "cannot generate valid strategies with these restrictions");
                return -1;
            }
        }
    }
    if (o->db && o->db_seed > 0 && !o->seed) {
        const sdb_rec **top = xmalloc((size_t)o->db_seed * sizeof(*top));
        size_t n = sdb_top(o->db, o->target, top, (size_t)o->db_seed), used = 0;
        for (size_t i = 0; i < n && used < p->n; i++) {
            strategy *s;
            sbuf e;
            if (!top[i]->ok)
                break;
            sb_init(&e);
            s = strategy_parse(top[i]->s, &e);
            sb_free(&e);
            if (!s)
                continue;
            {
                char *str = NULL;
                if (strategy_canon(&s, &str) < 0) {
                    strategy_free(s);
                    continue;
                }
                ind_free(&p->v[used]);
                p->v[used].s = s;
                p->v[used].str = str;
                p->v[used].fit = -1000;
                p->v[used].in_en = in_en || s->nin > 0;
                p->v[used].out_en = out_en || s->nout > 0;
                used++;
            }
        }
        free(top);
        if (used)
            LOGI("ga", "seeded %zu individual(s) from the strategy database", used);
    }
    return 0;
}

/* ---- genetic operators --------------------------------------------------- */

static int rejected(const ga_opts *o, const hall_of_fame *hall, const ga_ind *t)
{
    const hof_entry *e = hof_get(hall, t->str);
    if (e) {
        int all_neg = 1;
        for (size_t k = 0; k < e->n; k++)
            all_neg &= e->fits[k] < 0;
        if ((e->n >= 10 && all_neg) || e->n >= (size_t)o->allowed_retries)
            return 1;
    }
    return strategy_len(t->s) == 0 && !o->no_reject_empty;
}

/* mutation_crossover(). */
static void mutation_crossover(ga_opts *o, const hall_of_fame *hall, const pop_t *pop, pop_t *off)
{
    for (size_t i = 0; i < pop->n; i++)
        pop_push_copy(off, &pop->v[i]);
    for (size_t i = 1; i < off->n; i += 2) {
        ga_ind *a = &off->v[i - 1], *b = &off->v[i];
        strategy *ca, *cb;
        char *sa = NULL, *sb_ = NULL;
        if (rng_real() >= o->crossover_pb)
            continue;
        ca = strategy_copy(a->s);
        cb = strategy_copy(b->s);
        strategy_mate(ca, cb, 0.5, a->in_en, a->out_en);
        if (strategy_canon(&ca, &sa) == 0 && strategy_canon(&cb, &sb_) == 0) {
            strategy_free(a->s);
            strategy_free(b->s);
            free(a->str);
            free(b->str);
            a->s = ca;
            a->str = sa;
            b->s = cb;
            b->str = sb_;
        } else {
            strategy_free(ca);
            strategy_free(cb);
            free(sa);
        }
        a->fit = b->fit = -1000;
    }
    for (size_t i = 0; i < off->n; i++) {
        ga_ind *x = &off->v[i];
        if (rng_real() >= o->mutation_pb)
            continue;
        for (int tries = 0; tries < MAX_MUTATION_TRIES; tries++) {
            ga_ind t = {strategy_copy(x->s), NULL, -1000, x->in_en, x->out_en};
            strategy_mutate(&o->gen, t.s, t.in_en, t.out_en);
            if (strategy_canon(&t.s, &t.str) < 0 || rejected(o, hall, &t)) {
                ind_free(&t);
                continue;
            }
            ind_free(x);
            *x = t;
            break;
        }
        x->fit = -1000;
    }
}

/* selection_tournament(): k winners of tournaments among random entrants. */
static void select_tournament(const pop_t *from, size_t k, int tournsize, pop_t *to)
{
    for (size_t i = 0; i < k; i++) {
        const ga_ind *best = NULL;
        for (int j = 0; j < tournsize; j++) {
            const ga_ind *c = &from->v[rng_index(from->n)];
            if (!best || c->fit > best->fit)
                best = c;
        }
        pop_push_copy(to, best);
    }
}

static size_t unique_count(const pop_t *p)
{
    hall_of_fame h;
    size_t n;
    hof_init(&h);
    for (size_t i = 0; i < p->n; i++)
        hof_add(&h, p->v[i].str, 0);
    n = h.n;
    hof_free(&h);
    return n;
}

/* ---- files --------------------------------------------------------------- */

static void write_generation(const ga_opts *o, int gen, const pop_t *p)
{
    sbuf s;
    char *path;
    if (!o->out_dir)
        return;
    sb_init(&s);
    for (size_t i = 0; i < p->n; i++)
        sb_printf(&s, "%s%s", p->v[i].str, i + 1 < p->n ? "\n" : "");
    path = xasprintf("%s/generation%d.txt", o->out_dir, gen);
    if (write_file(path, s.data ? s.data : "", s.len) < 0)
        LOGW("ga", "cannot write %s", path);
    free(path);
    sb_free(&s);
}

static void write_hall(const ga_opts *o, int gen, const hall_of_fame *h)
{
    sbuf s;
    char *path;
    if (!o->out_dir)
        return;
    sb_init(&s);
    hof_format(h, &s);
    path = xasprintf("%s/hall%d.txt", o->out_dir, gen);
    if (write_file(path, s.data, s.len) < 0)
        LOGW("ga", "cannot write %s", path);
    free(path);
    sb_free(&s);
}

/* ---- checkpoint ---------------------------------------------------------- */

static char *params_hash(const ga_opts *o)
{
    sbuf s;
    char *h;
    sb_init(&s);
    sb_printf(&s, "pop=%d;elite=%d;trees=%d/%d;actions=%d/%d;seed=%s;%s", o->population, o->elite_clones,
              o->in_trees, o->out_trees, o->in_actions, o->out_actions, o->seed ? o->seed : "",
              o->params ? o->params : "");
    h = xasprintf("%016" PRIx64, str_hash(s.data));
    sb_free(&s);
    return h;
}

static void json_pop(jw *w, const pop_t *p)
{
    jw_arr(w);
    for (size_t i = 0; i < p->n; i++) {
        jw_obj(w);
        jw_kstr(w, "s", p->v[i].str);
        jw_kdbl(w, "f", p->v[i].fit);
        jw_kbool(w, "in", p->v[i].in_en);
        jw_kbool(w, "out", p->v[i].out_en);
        jw_obj_end(w);
    }
    jw_arr_end(w);
}

static int save_checkpoint(const ga_opts *o, int gen, const pop_t *pop, const pop_t *elite,
                           const hall_of_fame *hall)
{
    sbuf s;
    jw w;
    uint64_t st[4];
    char *hash, num[32];
    int rc;
    if (!o->checkpoint)
        return 0;
    sb_init(&s);
    jw_init(&w, &s);
    hash = params_hash(o);
    rng_get_state(st);
    jw_obj(&w);
    jw_kint(&w, "geneva_checkpoint", 1);
    jw_kstr(&w, "version", GENEVA_VERSION);
    jw_kstr(&w, "params", hash);
    jw_kint(&w, "generation", gen);
    jw_kuint(&w, "saved", plat_wall_ms());
    jw_key(&w, "rng");
    jw_arr(&w);
    for (int i = 0; i < 4; i++) {
        snprintf(num, sizeof(num), "%" PRIu64, st[i]); /* exact: doubles lose bits */
        jw_str(&w, num);
    }
    jw_arr_end(&w);
    jw_key(&w, "population");
    json_pop(&w, pop);
    jw_key(&w, "elite");
    json_pop(&w, elite);
    jw_key(&w, "hall");
    jw_arr(&w);
    for (size_t i = 0; i < hall->n; i++) {
        jw_obj(&w);
        jw_kstr(&w, "s", hall->v[i].str);
        jw_key(&w, "f");
        jw_arr(&w);
        for (size_t k = 0; k < hall->v[i].n; k++)
            jw_dbl(&w, hall->v[i].fits[k]);
        jw_arr_end(&w);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    jw_obj_end(&w);
    sb_putc(&s, '\n');
    rc = plat_write_atomic(o->checkpoint, s.data, s.len);
    if (rc < 0)
        LOGE("ga", "cannot write the checkpoint %s", o->checkpoint);
    free(hash);
    sb_free(&s);
    return rc;
}

static int load_pop(const json_val *arr, pop_t *p, sbuf *err)
{
    if (!arr || arr->type != JSON_ARR) {
        sb_puts(err, "checkpoint: bad population");
        return -1;
    }
    for (size_t i = 0; i < arr->n; i++) {
        const json_val *it = arr->items[i];
        const char *s = json_get_str(it, "s", NULL);
        if (!s || pop_push_text(p, s, json_get_num(it, "f", -1000), json_get_bool(it, "in", 1),
                                json_get_bool(it, "out", 1), err) < 0) {
            if (!err->len)
                sb_puts(err, "checkpoint: bad individual");
            return -1;
        }
    }
    return 0;
}

static int load_checkpoint(const ga_opts *o, int *gen, pop_t *pop, pop_t *elite, hall_of_fame *hall,
                           sbuf *err)
{
    size_t len;
    char *text = read_file(o->checkpoint, &len), *hash = NULL;
    const char *perr;
    json_val *v = NULL;
    const json_val *rng, *h;
    uint64_t st[4];
    int rc = -1;
    if (!text) {
        sb_printf(err, "cannot read the checkpoint %s", o->checkpoint);
        return -1;
    }
    v = json_parse(text, &perr);
    if (!v || v->type != JSON_OBJ || json_get_int(v, "geneva_checkpoint", 0) != 1) {
        sb_printf(err, "%s is not a geneva checkpoint", o->checkpoint);
        goto out;
    }
    hash = params_hash(o);
    if (strcmp(json_get_str(v, "params", ""), hash)) {
        if (!o->resume_force) {
            sb_printf(err, "%s was saved with other search settings (population, trees, protocols, "
                           "fields, actions, seed or target); give the same options, or --resume-force "
                           "to continue anyway",
                      o->checkpoint);
            goto out;
        }
        LOGW("ga", "the checkpoint was saved with other search settings; continuing as asked");
    }
    rng = json_get(v, "rng");
    if (!rng || rng->type != JSON_ARR || rng->n != 4) {
        sb_puts(err, "checkpoint: bad rng state");
        goto out;
    }
    for (int i = 0; i < 4; i++)
        if (rng->items[i]->type != JSON_STR || parse_u64(rng->items[i]->str, &st[i]) < 0) {
            sb_puts(err, "checkpoint: bad rng state");
            goto out;
        }
    if (load_pop(json_get(v, "population"), pop, err) < 0 || load_pop(json_get(v, "elite"), elite, err) < 0)
        goto out;
    h = json_get(v, "hall");
    if (!h || h->type != JSON_ARR) {
        sb_puts(err, "checkpoint: bad hall of fame");
        goto out;
    }
    for (size_t i = 0; i < h->n; i++) {
        const char *s = json_get_str(h->items[i], "s", NULL);
        const json_val *f = json_get(h->items[i], "f");
        if (!s || !f || f->type != JSON_ARR) {
            sb_puts(err, "checkpoint: bad hall of fame");
            goto out;
        }
        for (size_t k = 0; k < f->n; k++)
            hof_add(hall, s, f->items[k]->type == JSON_NUM ? f->items[k]->num : 0);
    }
    *gen = (int)json_get_int(v, "generation", 0);
    if (!pop->n || *gen < 0) {
        sb_puts(err, "checkpoint: empty population");
        goto out;
    }
    rng_set_state(st);
    rc = 0;
out:
    free(hash);
    json_free(v);
    free(text);
    return rc;
}

/* ---- the run ------------------------------------------------------------- */

static void record_db(ga_opts *o, const pop_t *off)
{
    if (!o->db || !o->eval)
        return;
    for (size_t i = 0; i < off->n; i++)
        sdb_add(o->db, off->v[i].str, o->target, off->v[i].fit, off->v[i].fit > 0);
}

static void emit_generation(int gen, size_t unique, double avg, const ga_ind *best, size_t evaluated)
{
    ev_t ev;
    if (!ev_enabled())
        return;
    ev_begin(&ev, "generation");
    jw_kint(&ev.w, "gen", gen);
    jw_kuint(&ev.w, "unique", unique);
    jw_kuint(&ev.w, "evaluated", evaluated);
    jw_kdbl(&ev.w, "avg_fitness", avg);
    jw_kdbl(&ev.w, "best_fitness", best->fit);
    jw_kstr(&ev.w, "best", best->str);
    ev_emit(&ev);
}

int ga_run(ga_opts *o, hall_of_fame *hall)
{
    pop_t pop = {0}, off = {0}, elite = {0}, next = {0};
    sbuf err;
    int gen = 0, rc = EXIT_OK, stopped = 0;

    sb_init(&err);
    if (o->resume) {
        if (load_checkpoint(o, &gen, &pop, &elite, hall, &err) < 0) {
            LOGE("ga", "%s", err.data);
            rc = EXIT_USAGE;
            goto out;
        }
        LOGI("ga", "resuming from %s at generation %d (%zu individuals, %zu in the hall of fame)",
             o->checkpoint, gen, pop.n, hall->n);
    } else {
        if (initialize_population(o, &pop, &err) < 0) {
            LOGE("ga", "%s", err.data);
            rc = EXIT_STRATEGY;
            goto out;
        }
        if (o->seed && pop_push_text(&elite, o->seed, -1000, o->in_trees > 0, o->out_trees > 0, &err) < 0) {
            LOGE("ga", "%s", err.data);
            rc = EXIT_STRATEGY;
            goto out;
        }
    }

    for (; gen < o->generations; gen++) {
        const ga_ind *best = NULL;
        double total = 0;
        size_t k;
        /* the state at the start of each generation is what a resume needs */
        if (save_checkpoint(o, gen, &pop, &elite, hall) < 0) {
            rc = EXIT_IO;
            break;
        }
        if (o->stop && *o->stop) {
            stopped = 1;
            break;
        }
        LOGI("ga", "Generation %d:", gen);
        write_generation(o, gen, &pop);

        pop_clear(&off);
        mutation_crossover(o, hall, &pop, &off);
        for (size_t i = 0; i < elite.n; i++)
            pop_push_copy(&off, &elite.v[i]);

        if (o->eval) {
            if (o->eval(o->eval_ctx, off.v, off.n) < 0 || (o->stop && *o->stop)) {
                if (o->stop && *o->stop) {
                    stopped = 1;
                    break;
                }
                LOGE("ga", "evaluation failed");
                rc = EXIT_FAIL;
                break;
            }
        } else {
            for (size_t i = 0; i < off.n; i++) {
                off.v[i].fit = 0;
                LOGD("ga", "[-1] Fitness 0: %s", off.v[i].str);
            }
        }
        record_db(o, &off);

        for (size_t i = 0; i < off.n; i++) {
            total += off.v[i].fit;
            if (!best || off.v[i].fit >= best->fit)
                best = &off.v[i];
            hof_add(hall, off.v[i].str, off.v[i].fit);
        }
        write_hall(o, gen, hall);
        LOGI("ga", "Generation: %d | Unique Individuals: %zu | Avg Fitness: %.2f | Best Fitness %g: %s", gen,
             unique_count(&pop), total / (double)off.n, best->fit, best->str);
        emit_generation(gen, unique_count(&pop), total / (double)off.n, best, off.n);

        k = off.n > (size_t)o->elite_clones ? off.n - (size_t)o->elite_clones : 0;
        pop_clear(&next);
        select_tournament(&off, k, o->tournsize, &next);
        pop_clear(&pop);
        {
            pop_t t = pop;
            pop = next;
            next = t;
        }
        pop_clear(&elite);
        for (int i = 0; i < o->elite_clones; i++)
            pop_push_copy(&elite, best);
    }
    if (rc == EXIT_OK && !stopped && save_checkpoint(o, gen, &pop, &elite, hall) < 0)
        rc = EXIT_IO;
    if (stopped)
        LOGI("ga", "stopped at generation %d%s%s", gen, o->checkpoint ? "; resume with --resume " : "",
             o->checkpoint ? o->checkpoint : "");

out:
    pop_free(&pop);
    pop_free(&off);
    pop_free(&elite);
    pop_free(&next);
    sb_free(&err);
    return rc;
}
