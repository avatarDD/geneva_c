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
    int bad_fool;      /* one sending the real data with what breaks a packet */
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

/* what breaks a packet, kept off the actions that send the real data */
static int is_fake(const char *kind)
{
    static const char *const fakes[] = {"xfake", "xfakedsplit", "xfakeddisorder", "xhostfake",
                                        "xrst",  "xsyndata",    "xsynack"};
    for (size_t i = 0; i < ARRAY_LEN(fakes); i++)
        if (!strcmp(kind, fakes[i]))
            return 1;
    return 0;
}

static int brk_key(const char *k)
{
    static const char *const brk[] = {"ttl",    "ip_ttl", "ip_autottl", "seq",   "ack",   "ts",
                                      "md5",    "flags+", "flags-",     "badsum", "ip6ext"};
    for (size_t j = 0; j < ARRAY_LEN(brk); j++)
        if (!strcmp(k, brk[j]))
            return 1;
    return !strncmp(k, "ip6_", 4);
}

static int fools_real(const xact *x)
{
    if (is_fake(x->kind->name))
        return 0;
    for (int i = 0; i < x->np; i++)
        if (brk_key(x->p[i].k))
            return 1;
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
        if (fools_real(x)) {
            if (!c->bad_fool)
                fprintf(stderr, "    breaks the real data: %s\n", x->text ? x->text : x->kind->name);
            c->bad_fool++;
        }
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
                                            "xsend",  "xmod",     "xrepeat",   "xwhen",       "xcutoff",
                                            "xstop",  "xtag",     "xtlsclone"};
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
    CHECK_INT(c.bad_fool, 0);
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
                  seen(&c, "xpcap") + seen(&c, "xlog"),
              0);
    /* the server's SYN,ACK: only with --agent */
    CHECK_INT(seen(&c, "xsynacksplit"), 0);
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
    /* xfake{ttl=4} retyped to xsplit and the like loses its ttl */
    CHECK_INT(c.bad_fool, 0);
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
    strat_xgen xg = {DIR_OUT, 0, 1, "", 0};
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
        /* nothing that changes TCP headers */
        for (int k = 0; k < ((xact *)x)->np; k++) {
            const char *key = ((xact *)x)->p[k].k;
            static const char *const tcp[] = {"seq", "ack", "ts", "md5", "flags+", "flags-", "tsup", "nopdel"};
            for (size_t j = 0; j < ARRAY_LEN(tcp); j++)
                if (!strcmp(key, tcp[j]))
                    CHECK_STR(key, "a key for UDP");
        }
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
    CHECK_INT(gen_disable_actions(&g, "sleep,trace,XFake,xsplit", &e), 0);
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
    strat_xgen xg = {DIR_OUT, 1, 1, "", 0};
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


/* Every variant is used: each action made where it fits, with each key it
 * takes and each value of the enumerated keys. Left out only: ifout and
 * fwmark (the host's setup), ipfrag_pos_icmp and ipfrag_pos (packets the
 * trees never see), what breaks a packet on actions sending the real data,
 * TCP's keys in a tree of UDP. */
typedef struct {
    char kind[32];
    char key[32];
    char vals[64][48];
    int nv;
} kcov;

static kcov g_cov[512];
static int g_ncov;

static kcov *cov_of(const char *kind, const char *key)
{
    for (int i = 0; i < g_ncov; i++)
        if (!strcmp(g_cov[i].kind, kind) && !strcmp(g_cov[i].key, key))
            return &g_cov[i];
    if (g_ncov == (int)ARRAY_LEN(g_cov))
        return NULL;
    snprintf(g_cov[g_ncov].kind, sizeof(g_cov[0].kind), "%s", kind);
    snprintf(g_cov[g_ncov].key, sizeof(g_cov[0].key), "%s", key);
    return &g_cov[g_ncov++];
}

static void cov_note(const xact *a)
{
    kcov *c = cov_of(a->kind->name, "");
    for (int i = 0; i < a->np; i++) {
        const char *v = a->p[i].v ? a->p[i].v : "";
        char head[48];
        size_t n = (v[0] >= '0' && v[0] <= '9') || v[0] == '-' ? 0 : strcspn(v, ":,=+-");
        /* the value's first word: "auto", "L7", "FLOW", "rnd", "host" ... */
        snprintf(head, sizeof(head), "%.*s", (int)(n < 40 ? n : 40), v);
        if (!strncmp(v, "L7:", 3) || !strncmp(v, "FLOW:", 5) || !strncmp(v, "TCP:", 4))
            snprintf(head, sizeof(head), "%.*s", (int)strcspn(v + strcspn(v, ":") + 1, ":") + (int)strcspn(v, ":") + 1, v);
        c = cov_of(a->kind->name, a->p[i].k);
        if (!c)
            continue;
        int dup = 0;
        for (int j = 0; j < c->nv && !dup; j++)
            dup = !strcmp(c->vals[j], head);
        if (!dup && c->nv < 64)
            snprintf(c->vals[c->nv++], sizeof(c->vals[0]), "%s", head);
    }
    (void)c;
}

static int cov_has(const char *kind, const char *key, const char *val)
{
    for (int i = 0; i < g_ncov; i++)
        if (!strcmp(g_cov[i].kind, kind) && !strcmp(g_cov[i].key, key)) {
            if (!val)
                return 1;
            for (int j = 0; j < g_cov[i].nv; j++)
                if (!strcmp(g_cov[i].vals[j], val))
                    return 1;
            fprintf(stderr, "    %s{%s}: never \"%s\"\n", kind, key, val);
            return 0;
        }
    fprintf(stderr, "    %s: never %s\n", kind, *key ? key : "made");
    return 0;
}

static void cov_run(strat_xgen g, int n)
{
    for (int i = 0; i < n; i++) {
        void *x = NULL;
        int kids = 0;
        if (xgen_random(&g, &x, &kids) != 1)
            continue;
        cov_note(x);
        for (int s = 0; s < 20; s++)
            if (xgen_mutate(&g, &x, kids) == 1)
                cov_note(x);
        xa_free(x);
    }
}

/* every key k takes, but those left out (above) */
static int cov_keys(const char *kind, int udp_only, int tcp_only_tree)
{
    static const char *const std[] = {
        "ttl",    "ip_ttl",     "ip6_ttl",      "ip_autottl",    "ip6_autottl", "ip6ext",       "ip6_hopbyhop",
        "ip6_hopbyhop2", "ip6_destopt", "ip6_destopt2", "ip6_routing", "ip6_ah",   "seq",       "ack",
        "ts",     "md5",        "flags+",       "flags-",        "tsup",        "nopdel",       "badsum",
        "repeats", "ipid",      "ipid_conn",    "ipfrag",        "ipfrag_disorder", "ipfrag_pos_tcp",
        "ipfrag_pos_udp", "ipfrag_next", "payload"};
    static const char *const tcp[] = {"seq", "ack", "ts", "md5", "flags+", "flags-", "tsup", "nopdel",
                                      "ipfrag_pos_tcp"};
    const xa_kind *k = xa_kind_find(kind);
    int ok = 1;
    for (size_t i = 0; i < ARRAY_LEN(std); i++) {
        const char *ck = xa_canon_key(k, std[i]);
        int skip = !ck || strcmp(ck, std[i]) || (!is_fake(kind) && brk_key(std[i])) ||
                   (tcp_only_tree && !strcmp(std[i], "ipfrag_pos_udp"));
        for (size_t j = 0; udp_only && j < ARRAY_LEN(tcp); j++)
            skip = skip || !strcmp(std[i], tcp[j]);
        if (!skip)
            ok &= cov_has(kind, std[i], NULL);
    }
    for (int i = 0; k->keys && k->keys[i]; i++)
        ok &= cov_has(kind, k->keys[i], NULL);
    return ok;
}

TEST(xgen_coverage)
{
    static const char *const tcp_out[] = {"xfake",   "xsplit",  "xdisorder", "xfakedsplit", "xfakeddisorder",
                                          "xtcpseg", "xhostfake", "xtlsrec", "xoob",        "xdrip",
                                          "xrst",    "xsyndata", "xsynack",  "xwssize",     "xhttp",
                                          "xtlsclone", "xtag",   "xsend",    "xmod",        "xrepeat",
                                          "xwhen",   "xstop",   "xcutoff"};
    static const char *const udp_out[] = {"xfake", "xtag", "xsend", "xmod", "xudplen", "xdhtdn",
                                          "xrepeat", "xwhen", "xstop", "xcutoff"};
    static const char *const srv_out[] = {"xfake", "xsplit", "xdisorder", "xfakedsplit", "xfakeddisorder", "xtcpseg",
                                          "xtlsrec", "xoob", "xdrip", "xrst", "xwsize", "xsynacksplit", "xtag",
                                          "xsend", "xmod", "xrepeat", "xwhen", "xstop", "xcutoff"};
    setup();
    g_ncov = 0;
    cov_run((strat_xgen){DIR_OUT, 1, 0, "", 0}, 4000);
    for (size_t i = 0; i < ARRAY_LEN(tcp_out); i++)
        CHECK(cov_keys(tcp_out[i], 0, 1));
    /* the enumerated values */
    {
        static const char *const ipid[] = {"seq", "rnd", "zero", "none"};
        static const char *const tlsmod[] = {"rnd", "rndsni", "dupsid", "padencap", "sni", "none"};
        static const char *const iff[] = {"cond_random", "cond_payload_str", "cond_true", "cond_false",
                                          "cond_tcp_has_ts", "L7:payload", "L7:proto", "FLOW:n", "FLOW:d",
                                          "FLOW:b", "FLOW:s", "FLOW:p", "FLOW:rn", "FLOW:rd", "FLOW:state",
                                          "FLOW:retrans", "TCP:flags"};
        static const char *const markers[] = {"host", "endhost", "sld", "midsld", "endsld", "method", "extlen",
                                              "sniext", ""};
        static const char *const dirs[] = {"in", "out", "both"};
        static const char *const ttl[] = {"", "auto"};
        static const char *const ip6ext[] = {"hopbyhop", "hopbyhop2", "destopt", "destopt2", "routing", "ah"};
        for (size_t i = 0; i < ARRAY_LEN(ipid); i++)
            CHECK(cov_has("xsend", "ipid", ipid[i]));
        for (size_t i = 0; i < ARRAY_LEN(tlsmod); i++)
            CHECK(cov_has("xfake", "tlsmod", tlsmod[i]));
        for (size_t i = 0; i < ARRAY_LEN(iff); i++)
            CHECK(cov_has("xwhen", "iff", iff[i]));
        for (size_t i = 0; i < ARRAY_LEN(markers); i++)
            CHECK(cov_has("xsplit", "pos", markers[i]));
        for (size_t i = 0; i < ARRAY_LEN(dirs); i++)
            CHECK(cov_has("xcutoff", "dir", dirs[i]));
        for (size_t i = 0; i < ARRAY_LEN(ttl); i++)
            CHECK(cov_has("xfake", "ttl", ttl[i]));
        for (size_t i = 0; i < ARRAY_LEN(ip6ext); i++)
            CHECK(cov_has("xfake", "ip6ext", ip6ext[i]));
        CHECK(cov_has("xfake", "blob", "fake_default_tls"));
        CHECK(cov_has("xfake", "blob", "gclone"));
        CHECK(cov_has("xfake", "payload", "gtag"));
        CHECK(cov_has("xfake", "md5", ""));
        CHECK(cov_has("xfake", "ipfrag", "ipfrag2") && cov_has("xfake", "ipfrag", ""));
    }
    g_ncov = 0;
    cov_run((strat_xgen){DIR_OUT, 0, 1, "", 0}, 3000);
    for (size_t i = 0; i < ARRAY_LEN(udp_out); i++)
        CHECK(cov_keys(udp_out[i], 1, 0));
    CHECK(cov_has("xfake", "payload", "quic_initial"));
    g_ncov = 0;
    cov_run((strat_xgen){DIR_IN, 1, 0, "", 0}, 300);
    CHECK(cov_keys("xwsize", 0, 1));
    g_ncov = 0;
    cov_run((strat_xgen){DIR_OUT, 1, 0, "", 1}, 4000);
    for (size_t i = 0; i < ARRAY_LEN(srv_out); i++)
        CHECK(cov_keys(srv_out[i], 0, 1));
    CHECK(cov_has("xsynacksplit", "mode", "syn") && cov_has("xsynacksplit", "mode", "synack") &&
          cov_has("xsynacksplit", "mode", "acksyn"));
    CHECK(cov_has("xfake", "payload", "tls_server_hello"));
    /* client-only actions stay off the server, and its inbound forest has none */
    for (int i = 0; i < g_ncov; i++)
        CHECK(strcmp(g_cov[i].kind, "xhostfake") && strcmp(g_cov[i].kind, "xsyndata") &&
              strcmp(g_cov[i].kind, "xtlsclone") && strcmp(g_cov[i].kind, "xhttp"));
    {
        void *x = NULL;
        int kids = 0;
        strat_xgen in = {DIR_IN, 1, 0, "", 1};
        CHECK_INT(xgen_random(&in, &x, &kids), 0);
    }
    teardown();
}

void suite_xgen(void)
{
    RUN(xgen_coverage);
    RUN(xgen_new);
    RUN(xgen_mutate_seed);
    RUN(xgen_transport);
    RUN(xgen_disable);
    RUN(xgen_untouched);
}

#else
void suite_xgen(void) {}
#endif
