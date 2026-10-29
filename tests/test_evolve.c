/* Genetic operators, the GA loop, checkpoints and the strategy database. */
#include <stdlib.h>
#include <string.h>

#include "evolve.h"
#include "log.h"
#include "mutate.h"
#include "plat.h"
#include "rng.h"
#include "sdb.h"
#include "test.h"
#include "util.h"

/* Walks every action of a strategy. */
static void walk(const action *a, strat_dir dir, int *bad_in, int *bad_shape, int *types)
{
    if (!a)
        return;
    types[a->type]++;
    if (dir == DIR_IN && a->type != ACT_TAMPER && a->type != ACT_DROP)
        (*bad_in)++;
    if ((a->type == ACT_DROP || a->type == ACT_TRACE) && (a->left || a->right))
        (*bad_shape)++;
    if (a->right && a->type != ACT_DUPLICATE && a->type != ACT_FRAGMENT)
        (*bad_shape)++;
    walk(a->left, dir, bad_in, bad_shape, types);
    walk(a->right, dir, bad_in, bad_shape, types);
}

typedef struct {
    int bad_in, bad_shape, types[ACT_TRACE + 1], gas, triggers;
    int fields_ok; /* every trigger and tamper uses only TCP:flags */
} census;

static void count(const strategy *s, census *c)
{
    for (int d = 0; d < 2; d++) {
        atree **f = d ? s->in : s->out;
        size_t n = d ? s->nin : s->nout;
        for (size_t i = 0; i < n; i++) {
            c->triggers++;
            c->gas += f[i]->trig.has_gas;
            walk(f[i]->root, d ? DIR_IN : DIR_OUT, &c->bad_in, &c->bad_shape, c->types);
        }
    }
}

static void check_fields(const action *a, int *bad)
{
    if (!a)
        return;
    if (a->type == ACT_TAMPER && (a->layer != LAYER_TCP || strcmp(a->field, "flags")))
        (*bad)++;
    check_fields(a->left, bad);
    check_fields(a->right, bad);
}

static void test_operators(void)
{
    gen_ctx g;
    census c;
    int parsed = 0, canon = 0, total = 0;
    t_current = "mutate";
    memset(&g, 0, sizeof(g));
    memset(&c, 0, sizeof(c));
    g.disabled[ACT_SLEEP] = g.disabled[ACT_TRACE] = 1;
    fields_reset_restrictions();
    for (int i = 0; i < 300; i++) {
        strategy *s = strategy_random(&g, i % 3, 1 + i % 2, 2, 2);
        for (int k = 0; k < 30; k++) {
            sbuf t, e;
            strategy *p;
            strategy_mutate(&g, s, 1, 1);
            total++;
            sb_init(&t);
            sb_init(&e);
            strategy_print(s, &t);
            p = strategy_parse(t.data, &e);
            if (p) {
                parsed++;
                strategy_free(p);
            } else {
                fprintf(stderr, "    unparseable: %s (%s)\n", t.data, e.data);
            }
            sb_free(&t);
            sb_free(&e);
            if (strategy_canon(&s, NULL) == 0)
                canon++;
            count(s, &c);
        }
        strategy_free(s);
    }
    /* the tree shape is always valid; only rare values fail to round-trip */
    CHECK_INT(parsed, total);
    CHECK(canon >= total * 95 / 100);
    CHECK_INT(c.bad_in, 0);
    CHECK_INT(c.bad_shape, 0);
    CHECK_INT(c.types[ACT_SLEEP] + c.types[ACT_TRACE], 0);
    CHECK(c.types[ACT_TAMPER] > 0 && c.types[ACT_DUPLICATE] > 0 && c.types[ACT_FRAGMENT] > 0 &&
          c.types[ACT_DROP] > 0);
    CHECK(c.gas > 0);
}

static void test_restrictions(void)
{
    gen_ctx g;
    census c;
    trigger fixed;
    sbuf e;
    int bad = 0, wrong_trigger = 0;
    t_current = "mutate restrictions";
    memset(&g, 0, sizeof(g));
    memset(&c, 0, sizeof(c));
    sb_init(&e);
    g.disabled[ACT_SLEEP] = g.disabled[ACT_TRACE] = g.disabled[ACT_DUPLICATE] = g.disabled[ACT_FRAGMENT] = 1;
    g.no_gas = 1;
    CHECK_INT(fields_restrict("TCP", "flags", "", &e), 0);
    for (int i = 0; i < 200; i++) {
        strategy *s = strategy_random(&g, 1, 1, 3, 3);
        for (int k = 0; k < 20; k++)
            strategy_mutate(&g, s, 1, 1);
        count(s, &c);
        for (size_t t = 0; t < s->nout; t++)
            check_fields(s->out[t]->root, &bad);
        for (size_t t = 0; t < s->nin; t++)
            check_fields(s->in[t]->root, &bad);
        strategy_free(s);
    }
    CHECK_INT(bad, 0);
    CHECK_INT(c.gas, 0);
    CHECK_INT(c.types[ACT_DUPLICATE] + c.types[ACT_FRAGMENT], 0);

    /* --fix-trigger: every tree gets that trigger */
    CHECK_INT(trigger_parse(&fixed, "TCP:flags:PA", &e), 0);
    g.fixed = &fixed;
    fields_reset_restrictions();
    for (int i = 0; i < 100; i++) {
        strategy *s = strategy_random(&g, 1, 2, 2, 2);
        for (int k = 0; k < 10; k++)
            strategy_mutate(&g, s, 1, 1);
        for (size_t t = 0; t < s->nout; t++) {
            sbuf b;
            sb_init(&b);
            trigger_print(&s->out[t]->trig, &b);
            wrong_trigger += strcmp(b.data, "TCP:flags:PA") != 0;
            sb_free(&b);
        }
        strategy_free(s);
    }
    CHECK_INT(wrong_trigger, 0);
    trigger_clear(&fixed);
    CHECK_INT(gen_disable_actions(&g, "drop,bogus", &e), -1);
    sb_free(&e);
}

static void test_real_packets(void)
{
    /* IPv4 TCP SYN 10.0.0.1:40000 -> 10.0.0.2:80 */
    static const uint8_t syn[] = {
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 10,   0,    0,    1,
        10,   0,    0,    2,    0x9c, 0x40, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x72, 0x10, 0x00, 0x00, 0x00, 0x00,
    };
    gen_ctx g;
    gpkt *p = pkt_parse(syn, sizeof(syn));
    sbuf e;
    int fired_all = 1;
    t_current = "mutate real packets";
    CHECK(p != NULL);
    if (!p)
        return;
    memset(&g, 0, sizeof(g));
    sb_init(&e);
    g.no_gas = 1;
    g.env = &p;
    g.nenv = 1;
    fields_restrict("TCP,IP", "", "", &e);
    /* new triggers take their values from the captured packet: they fire on it */
    for (int i = 0; i < 100; i++) {
        strategy *s = strategy_random(&g, 0, 2, 1, 1);
        pktlist out = {0};
        int fired = strategy_apply(s, pkt_copy(p), DIR_OUT, &out);
        if (fired != (int)s->nout) {
            sbuf b;
            sb_init(&b);
            strategy_print(s, &b);
            fprintf(stderr, "    did not fire: %s\n", b.data);
            sb_free(&b);
            fired_all = 0;
        }
        pktlist_free(&out);
        strategy_free(s);
    }
    CHECK(fired_all);
    fields_reset_restrictions();
    pkt_free(p);
    sb_free(&e);
}

static void test_crossover(void)
{
    gen_ctx g;
    int kept = 1;
    t_current = "crossover";
    memset(&g, 0, sizeof(g));
    fields_reset_restrictions();
    for (int i = 0; i < 300; i++) {
        strategy *a = strategy_random(&g, 1, 2, 3, 3), *b = strategy_random(&g, 1, 1 + i % 3, 2, 2);
        size_t before = strategy_len(a) + strategy_len(b);
        size_t trees = a->nout + a->nin + b->nout + b->nin;
        sbuf e, t;
        strategy *pa, *pb;
        strategy_mate(a, b, 1.0, 1, 1);
        /* subtrees and trees only move between the two */
        kept &= strategy_len(a) + strategy_len(b) == before;
        kept &= a->nout + a->nin + b->nout + b->nin == trees;
        sb_init(&e);
        sb_init(&t);
        strategy_print(a, &t);
        pa = strategy_parse(t.data, &e);
        sb_reset(&t);
        strategy_print(b, &t);
        pb = strategy_parse(t.data, &e);
        CHECK(pa != NULL && pb != NULL);
        strategy_free(pa);
        strategy_free(pb);
        sb_free(&e);
        sb_free(&t);
        strategy_free(a);
        strategy_free(b);
    }
    CHECK(kept);
}

/* ---- the GA -------------------------------------------------------------- */

static int want_drop(void *ctx, ga_ind *inds, size_t n)
{
    int *calls = ctx;
    (*calls)++;
    for (size_t i = 0; i < n; i++)
        inds[i].fit = strstr(inds[i].str, "drop") ? 400.0 - 10.0 * (double)strategy_len(inds[i].s) : -100;
    return 0;
}

static char *run_ga(ga_opts *o, uint64_t seed, int *rc)
{
    hall_of_fame h;
    const hof_entry *best[3];
    sbuf s;
    size_t n;
    hof_init(&h);
    if (seed)
        rng_global_seed(seed);
    *rc = ga_run(o, &h);
    sb_init(&s);
    n = hof_best(&h, best, 3);
    for (size_t i = 0; i < n; i++)
        sb_printf(&s, "%zu %s\n", best[i]->n, best[i]->str);
    sb_printf(&s, "hall=%zu\n", h.n);
    hof_free(&h);
    return sb_take(&s);
}

static void test_ga(void)
{
    ga_opts o;
    char path[64], dbpath[64];
    char *full, *part, *resumed;
    int rc, calls = 0;
    sdb *db;
    sbuf e;
    log_level saved = log_get_level();
    t_current = "ga";
    log_set_level(LOG_WARN);
    snprintf(path, sizeof(path), "geneva-test-%d.ckpt", plat_getpid());
    snprintf(dbpath, sizeof(dbpath), "geneva-test-%d.jsonl", plat_getpid());
    remove(path);
    remove(dbpath);
    sb_init(&e);
    fields_restrict("TCP", "", "", &e);

    ga_opts_default(&o);
    o.population = 40;
    o.generations = 8;
    o.eval = want_drop;
    o.eval_ctx = &calls;
    full = run_ga(&o, 99, &rc);
    CHECK_INT(rc, 0);
    CHECK_INT(calls, 8);
    CHECK(strstr(full, "drop") != NULL); /* the GA finds what the evaluator rewards */

    /* 3 generations, then resume to 8: the same result as one run */
    o.checkpoint = path;
    o.generations = 3;
    part = run_ga(&o, 99, &rc);
    CHECK_INT(rc, 0);
    o.generations = 8;
    o.resume = 1;
    resumed = run_ga(&o, 12345, &rc); /* a different seed: the checkpoint restores the state */
    CHECK_INT(rc, 0);
    CHECK_STR(resumed, full);
    free(part);
    free(resumed);

    /* other settings are refused unless forced */
    o.population = 41;
    resumed = run_ga(&o, 0, &rc);
    CHECK_INT(rc, 2);
    free(resumed);
    o.resume_force = 1;
    resumed = run_ga(&o, 0, &rc);
    CHECK_INT(rc, 0);
    free(resumed);

    /* stopped before the first generation: nothing evaluated, resumable */
    {
        volatile sig_atomic_t stop = 1;
        ga_opts_default(&o);
        o.population = 10;
        o.generations = 5;
        o.eval = want_drop;
        calls = 0;
        o.eval_ctx = &calls;
        o.checkpoint = path;
        o.stop = &stop;
        resumed = run_ga(&o, 1, &rc);
        CHECK_INT(rc, 0);
        CHECK_INT(calls, 0);
        free(resumed);
        stop = 0;
        o.resume = 1;
        resumed = run_ga(&o, 0, &rc);
        CHECK_INT(calls, 5);
        free(resumed);
    }

    /* the database collects evaluations and seeds the next run */
    db = sdb_open(dbpath, &e);
    CHECK(db != NULL);
    ga_opts_default(&o);
    o.population = 20;
    o.generations = 3;
    o.eval = want_drop;
    o.eval_ctx = &calls;
    o.db = db;
    o.target = "t";
    free(run_ga(&o, 5, &rc));
    CHECK(sdb_count(db) > 0);
    {
        const sdb_rec *top[1];
        CHECK_INT(sdb_top(db, "t", top, 1), 1);
        CHECK(strstr(top[0]->s, "drop") != NULL && top[0]->ok > 0);
        /* a new run seeded from it has the best strategy in generation 0 */
        o.generations = 1;
        o.db_seed = 3;
        o.mutation_pb = 0;
        o.crossover_pb = 0;
        o.elite_clones = 0;
        {
            hall_of_fame h;
            hof_init(&h);
            CHECK_INT(ga_run(&o, &h), 0);
            CHECK(hof_get(&h, top[0]->s) != NULL);
            hof_free(&h);
        }
    }
    sdb_close(db);
    remove(path);
    remove(dbpath);
    fields_reset_restrictions();
    sb_free(&e);
    free(full);
    log_set_level(saved);
}

static void test_sdb(void)
{
    char path[64];
    sdb *db;
    sbuf e;
    const sdb_rec *top[4];
    t_current = "sdb";
    snprintf(path, sizeof(path), "geneva-test-%d.db", plat_getpid());
    remove(path);
    sb_init(&e);
    db = sdb_open(path, &e);
    CHECK(db != NULL);
    if (!db)
        return;
    sdb_add(db, "[TCP:flags:S]-drop-| \\/", "a", 100, 1);
    sdb_add(db, "[TCP:flags:S]-drop-| \\/", "a", -50, 0);
    sdb_add(db, "[TCP:flags:S]-drop-| \\/", "b", 10, 1);
    sdb_add(db, "[TCP:flags:PA]-drop-| \\/", "a", 300, 1);
    sdb_add(db, "[TCP:flags:R]-drop-| \\/", "a", -10, 0);
    CHECK_INT(sdb_count(db), 4);
    sdb_close(db);

    db = sdb_open(path, &e); /* merged from the appended lines */
    CHECK_INT(sdb_count(db), 4);
    {
        const sdb_rec *r = sdb_find(db, "[TCP:flags:S]-drop-| \\/", "a");
        CHECK(r != NULL);
        if (r) {
            CHECK_INT(r->runs, 2);
            CHECK_INT(r->ok, 1);
            CHECK(r->fit_sum == 50 && r->fit_best == 100);
            CHECK(r->last_ok > 0 && r->first <= r->last);
        }
    }
    CHECK_INT(sdb_top(db, "a", top, 4), 3);
    CHECK_STR(top[0]->s, "[TCP:flags:PA]-drop-| \\/"); /* 100% beats 50% */
    CHECK_STR(top[2]->s, "[TCP:flags:R]-drop-| \\/");
    CHECK_INT(sdb_top(db, NULL, top, 4), 4);
    CHECK_INT(sdb_prune(db, 0, 1, 0), 1); /* never succeeded */
    CHECK_INT(sdb_count(db), 3);
    CHECK_INT(sdb_prune(db, 2, 0, 0), 2); /* fewer than 2 runs */
    sdb_close(db);
    db = sdb_open(path, &e);
    CHECK_INT(sdb_count(db), 1);
    {
        sdb_rec r;
        CHECK_INT(sdb_rec_parse("{\"s\":\"x\",\"runs\":1,\"ok\":2}", &r), -1); /* ok > runs */
        CHECK_INT(sdb_rec_parse("not json", &r), -1);
    }
    sdb_close(db);
    remove(path);
    sb_free(&e);
}

void suite_evolve(void)
{
    test_operators();
    test_restrictions();
    test_real_packets();
    test_crossover();
    test_ga();
    test_sdb();
}
