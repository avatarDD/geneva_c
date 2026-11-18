/* The genetic operators of the x-actions (src/ext/xgen.c, mutate.c): geneva
 * evolve --ext makes x-actions and changes their parameters. */
#include <stdlib.h>
#include <string.h>

#include "mutate.h"
#include "pkt.h"
#include "rng.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/blob.h"
#  include "ext/xact.h"
#  include "ext/xtrig.h"

#  define MAXK 64

typedef struct {
    const char *name[MAXK];
    int n[MAXK];
    int nk;
    int x, other;      /* x-actions, Geneva's */
    int bad_dir;       /* an x-action its forest does not take */
    char *texts[4096]; /* distinct x-actions as printed */
    int nt;
} xcensus;

static void note(xcensus *c, const char *name)
{
    for (int i = 0; i < c->nk; i++)
        if (!strcmp(c->name[i], name)) {
            c->n[i]++;
            return;
        }
    if (c->nk < MAXK) {
        c->name[c->nk] = name;
        c->n[c->nk++] = 1;
    }
}

static int seen(const xcensus *c, const char *name)
{
    for (int i = 0; i < c->nk; i++)
        if (!strcmp(c->name[i], name))
            return c->n[i];
    return 0;
}

static void walk(const action *a, strat_dir dir, xcensus *c)
{
    if (!a)
        return;
    if (a->type == ACT_X) {
        const xact *x = a->x;
        sbuf t;
        int dup = 0;
        c->x++;
        note(c, x->kind->name);
        if (dir == DIR_IN && strcmp(x->kind->name, "xwsize"))
            c->bad_dir++;
        sb_init(&t);
        action_print(a, &t);
        for (int i = 0; i < c->nt && !dup; i++)
            dup = !strcmp(c->texts[i], t.data);
        if (!dup && c->nt < (int)ARRAY_LEN(c->texts))
            c->texts[c->nt++] = sb_take(&t);
        else
            sb_free(&t);
    } else {
        c->other++;
    }
    walk(a->left, dir, c);
    walk(a->right, dir, c);
}

static void census_of(const strategy *s, xcensus *c)
{
    for (size_t i = 0; i < s->nout; i++)
        walk(s->out[i]->root, DIR_OUT, c);
    for (size_t i = 0; i < s->nin; i++)
        walk(s->in[i]->root, DIR_IN, c);
}

static void census_free(xcensus *c)
{
    for (int i = 0; i < c->nt; i++)
        free(c->texts[i]);
    memset(c, 0, sizeof(*c));
}

/* how many distinct printed x-actions of kind name */
static int variants(const xcensus *c, const char *name)
{
    int n = 0;
    size_t l = strlen(name);
    for (int i = 0; i < c->nt; i++)
        if (!strncmp(c->texts[i], name, l) && (c->texts[i][l] == '{' || c->texts[i][l] == '(' || !c->texts[i][l]))
            n++;
    return n;
}

/* every strategy prints back the same after parsing */
static int canon_ok(strategy **s)
{
    sbuf t, e;
    strategy *p;
    int ok;
    sb_init(&t);
    sb_init(&e);
    strategy_print(*s, &t);
    p = strategy_parse(t.data, &e);
    if (!p)
        fprintf(stderr, "    unparseable: %s (%s)\n", t.data, e.data);
    ok = p != NULL;
    strategy_free(p);
    sb_free(&t);
    sb_free(&e);
    return ok && strategy_canon(s, NULL) == 0;
}

static void setup(void)
{
    strategy_set_xact(&xact_ops);
    strategy_set_xtrig(&xtrig_ops);
    blob_reset();
    fields_reset_restrictions();
}

static void teardown(void)
{
    strategy_set_xact(NULL);
    strategy_set_xtrig(NULL);
    blob_free_all();
    fields_reset_restrictions();
}

/* new strategies and mutations: x-actions of every client-side kind, all
 * valid, with many parameter sets */
TEST(xgen_new)
{
    gen_ctx g;
    xcensus c;
    int total = 0, ok = 0;
    sbuf e;
    static const char *const tcp_kinds[] = {"xfake",  "xsplit",  "xdisorder", "xfakedsplit", "xfakeddisorder",
                                            "xtcpseg", "xhostfake", "xtlsrec",  "xoob",        "xdrip",
                                            "xrst",   "xsyndata", "xsynack",   "xwssize",     "xhttp",
                                            "xsend",  "xmod",     "xrepeat",   "xwhen",       "xcutoff"};
    setup();
    memset(&g, 0, sizeof(g));
    memset(&c, 0, sizeof(c));
    sb_init(&e);
    CHECK_INT(gen_disable_actions(&g, "sleep,trace", &e), 0);
    CHECK_INT(fields_restrict("TCP", "", "", &e), 0); /* evolve's default */
    for (int i = 0; i < 300; i++) {
        strategy *s = strategy_random(&g, i % 3 ? 0 : 1, 1 + i % 2, 2, 2);
        for (int k = 0; k < 20; k++) {
            strategy_mutate(&g, s, 1, 1);
            total++;
            ok += canon_ok(&s);
            census_of(s, &c);
        }
        strategy_free(s);
    }
    CHECK_INT(ok, total);
    CHECK_INT(c.bad_dir, 0);
    CHECK(c.x > 0 && c.other > 0);
    for (size_t i = 0; i < ARRAY_LEN(tcp_kinds); i++) {
        if (!seen(&c, tcp_kinds[i]))
            fprintf(stderr, "    never made: %s\n", tcp_kinds[i]);
        CHECK(seen(&c, tcp_kinds[i]) > 0);
    }
    /* UDP only ones need a UDP tree (--protos TCP) */
    CHECK_INT(seen(&c, "xudplen") + seen(&c, "xdhtdn"), 0);
    /* never made: they need the other end, or do nothing a censor sees */
    CHECK_INT(seen(&c, "xwgobfs") + seen(&c, "xippxor") + seen(&c, "xudp2icmp") + seen(&c, "xsynhide") +
                  seen(&c, "xpcap") + seen(&c, "xlog") + seen(&c, "xtag") + seen(&c, "xtlsclone"),
              0);
    CHECK(variants(&c, "xfake") > 50);
    CHECK(variants(&c, "xsplit") > 30);
    census_free(&c);
    sb_free(&e);
    gen_ctx_free(&g);
    teardown();
}

/* a seed's x-actions: their parameters change, the kind changes now and
 * then (keeping its subtrees), and the result stays a valid strategy */
TEST(xgen_mutate_seed)
{
    gen_ctx g;
    xcensus c;
    sbuf e;
    int ttl_changed = 0, pos_changed = 0, retyped = 0, total = 0, ok = 0;
    const char *seed = "[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=4}(xsplit{pos=1,midsld},)-| \\/";
    setup();
    memset(&g, 0, sizeof(g));
    memset(&c, 0, sizeof(c));
    sb_init(&e);
    for (int i = 0; i < 400; i++) {
        strategy *s = strategy_parse(seed, &e);
        sbuf t;
        CHECK(s != NULL);
        if (!s)
            break;
        for (int k = 0; k < 3; k++)
            strategy_mutate(&g, s, 0, 1);
        total++;
        ok += canon_ok(&s);
        census_of(s, &c);
        sb_init(&t);
        strategy_print(s, &t);
        ttl_changed += strstr(t.data, "xfake{") && !strstr(t.data, "ttl=4") && strstr(t.data, "ttl=");
        pos_changed += strstr(t.data, "xsplit{") && !strstr(t.data, "pos=1,midsld");
        retyped += !strstr(t.data, "xfake") || !strstr(t.data, "xsplit");
        sb_free(&t);
        strategy_free(s);
    }
    CHECK_INT(ok, total);
    CHECK(ttl_changed > 0);
    CHECK(pos_changed > 0);
    CHECK(retyped > 0);
    census_free(&c);
    sb_free(&e);
    gen_ctx_free(&g);
    teardown();
}

/* a UDP tree gets the UDP kinds only; an inbound one only xwsize */
TEST(xgen_transport)
{
    xcensus c;
    strat_xgen xg = {DIR_OUT, 0, 1, ""};
    setup();
    memset(&c, 0, sizeof(c));
    for (int i = 0; i < 2000; i++) {
        void *x = NULL;
        int kids = 0;
        CHECK_INT(xgen_random(&xg, &x, &kids), 1);
        if (!x)
            break;
        note(&c, ((xact *)x)->kind->name);
        xa_free(x);
    }
    CHECK(seen(&c, "xfake") > 0 && seen(&c, "xudplen") > 0 && seen(&c, "xdhtdn") > 0 && seen(&c, "xsend") > 0);
    CHECK_INT(seen(&c, "xsplit") + seen(&c, "xdisorder") + seen(&c, "xtcpseg") + seen(&c, "xoob") +
                  seen(&c, "xhttp") + seen(&c, "xsyndata"),
              0);
    memset(&c, 0, sizeof(c));
    xg.dir = DIR_IN;
    xg.tcp = 1;
    xg.udp = 0;
    for (int i = 0; i < 200; i++) {
        void *x = NULL;
        int kids = 0;
        CHECK_INT(xgen_random(&xg, &x, &kids), 1);
        if (!x)
            break;
        note(&c, ((xact *)x)->kind->name);
        xa_free(x);
    }
    CHECK_INT(seen(&c, "xwsize"), 200);
    /* nothing comes in over UDP */
    xg.tcp = 0;
    xg.udp = 1;
    {
        void *x = NULL;
        int kids = 0;
        CHECK_INT(xgen_random(&xg, &x, &kids), 0);
    }
    /* a fake over UDP draws a UDP blob, never a TLS record */
    xg.dir = DIR_OUT;
    for (int i = 0; i < 300; i++) {
        void *x = NULL;
        int kids = 0;
        const char *b;
        if (xgen_random(&xg, &x, &kids) != 1)
            continue;
        b = xa_raw(x, "blob");
        if (!strcmp(((xact *)x)->kind->name, "xfake")) {
            CHECK(b != NULL);
            if (b && (!strcmp(b, "fake_default_tls") || !strcmp(b, "fake_default_http")))
                CHECK_STR(b, "a UDP blob");
        }
        xa_free(x);
    }
    teardown();
}

/* --disable-action: x stops every x-action, names stop those */
TEST(xgen_disable)
{
    gen_ctx g;
    xcensus c;
    sbuf e;
    const char *seed = "[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=4}(xsplit{pos=1,midsld},)-| \\/";
    setup();
    memset(&g, 0, sizeof(g));
    memset(&c, 0, sizeof(c));
    sb_init(&e);
    CHECK_INT(gen_disable_actions(&g, "sleep,trace,xfake,xsplit", &e), 0);
    CHECK_STR(g.xskip, "xfake,xsplit");
    for (int i = 0; i < 300; i++) {
        strategy *s = strategy_random(&g, 0, 1, 3, 3);
        for (int k = 0; k < 5; k++)
            strategy_mutate(&g, s, 0, 1);
        census_of(s, &c);
        strategy_free(s);
    }
    CHECK(c.x > 0);
    CHECK_INT(seen(&c, "xfake") + seen(&c, "xsplit"), 0);
    census_free(&c);
    gen_ctx_free(&g);

    memset(&g, 0, sizeof(g));
    CHECK_INT(gen_disable_actions(&g, "sleep,trace,x", &e), 0);
    CHECK_INT(g.disabled[ACT_X], 1);
    for (int i = 0; i < 200; i++) {
        strategy *s = strategy_parse(seed, &e), *r;
        sbuf t;
        for (int k = 0; k < 5; k++)
            strategy_mutate(&g, s, 0, 1);
        census_of(s, &c);
        /* the seed's x-actions stay as written */
        sb_init(&t);
        strategy_print(s, &t);
        if (strstr(t.data, "xfake"))
            CHECK(strstr(t.data, "xfake{blob=fake_default_tls;ttl=4}") != NULL);
        sb_free(&t);
        strategy_free(s);
        r = strategy_random(&g, 0, 1, 3, 3);
        census_of(r, &c);
        strategy_free(r);
    }
    CHECK_INT(c.x - seen(&c, "xfake") - seen(&c, "xsplit"), 0);
    census_free(&c);
    gen_ctx_free(&g);

    sb_reset(&e);
    memset(&g, 0, sizeof(g));
    CHECK_INT(gen_disable_actions(&g, "xnothing", &e), -1);
    CHECK(strstr(e.data, "xnothing") != NULL);
    teardown();
    /* without --ext there are no x-actions to name */
    sb_reset(&e);
    memset(&g, 0, sizeof(g));
    CHECK_INT(gen_disable_actions(&g, "x", &e), -1);
    sb_free(&e);
}

/* the actions left as they are: the operators make no obfuscator and do not
 * touch one */
TEST(xgen_untouched)
{
    strat_xgen xg = {DIR_OUT, 1, 1, ""};
    void *x = NULL;
    int kids = 0;
    sbuf e;
    setup();
    sb_init(&e);
    CHECK_INT(xa_parse("xlog", "msg=hello", DIR_OUT, &x, &kids, &e), 1);
    CHECK_INT(xgen_mutate(&xg, &x, kids), 0);
    xa_free(x);
    sb_free(&e);
    teardown();
}

void suite_xgen(void)
{
    RUN(xgen_new);
    RUN(xgen_mutate_seed);
    RUN(xgen_transport);
    RUN(xgen_disable);
    RUN(xgen_untouched);
}

#else
void suite_xgen(void) {}
#endif
