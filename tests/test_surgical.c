/* The surgical path and the policy of --ext (X10b, src/ext/policy.c, the
 * decision in src/ext/ext.c): the policy's snapshots and their QSBR, and
 * which connections the engine lets go past the queue. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine_int.h"
#include "ext_opt.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ext.h"
#  include "ext/fwx.h"
#  include "ext/policy.h"

/* ---- the policy ---- */

TEST(pol_snapshots)
{
    const xpol_snap *s, *s2;
    const char *k[XPOL_KEYS] = {"tcp/443", "10.0.0.0/24", "10.0.0.7", ""};
    unsigned gen;
    size_t keys, pending;
    xpol_init(2);
    s = xpol_enter(0);
    CHECK(s != NULL);
    CHECK_INT((int)xpol_count(s), 0);
    CHECK_INT(xpol_any_impaired(s, k), 0);
    xpol_leave(0);

    xpol_set("10.0.0.0/24", XPOL_IMPAIRED);
    xpol_set("b.example", XPOL_IMPAIRED);
    xpol_set("a.example", XPOL_IMPAIRED);
    xpol_set("a.example", XPOL_IMPAIRED); /* no change */
    CHECK_INT(xpol_publish(), 1);
    CHECK_INT(xpol_publish(), 0); /* nothing new */
    s = xpol_enter(0);
    CHECK_INT((int)xpol_count(s), 3);
    CHECK_INT(xpol_state(s, "a.example"), XPOL_IMPAIRED);
    CHECK_INT(xpol_state(s, "b.example"), XPOL_IMPAIRED);
    CHECK_INT(xpol_state(s, "c.example"), XPOL_HEALTHY);
    CHECK_INT(xpol_any_impaired(s, k), 1);

    /* reader 0 holds snapshot 1: a new one is published, 1 stays */
    xpol_set("10.0.0.0/24", XPOL_HEALTHY);
    CHECK_INT(xpol_publish(), 1);
    xpol_stats(&gen, &keys, &pending);
    CHECK_INT(gen, 2);
    CHECK_INT((int)keys, 2);
    CHECK_INT((int)pending, 1);
    CHECK_INT(xpol_state(s, "10.0.0.0/24"), XPOL_IMPAIRED); /* still readable */
    s2 = xpol_enter(1);
    CHECK_INT(xpol_any_impaired(s2, k), 0);
    xpol_leave(1);
    /* while reader 0 stays, more snapshots fill the slots; a publish
     * waits for a free one instead of overwriting */
    for (int i = 0; i < XPOL_SLOTS + 2; i++) {
        char key[32];
        snprintf(key, sizeof(key), "k%d", i);
        xpol_set(key, XPOL_IMPAIRED);
        xpol_publish();
    }
    xpol_stats(&gen, &keys, &pending);
    CHECK_INT((int)pending, XPOL_SLOTS - 1);
    CHECK_INT(gen, XPOL_SLOTS);
    CHECK_INT(xpol_state(s, "a.example"), XPOL_IMPAIRED);
    xpol_leave(0);
    /* reader 0 quiescent: the waiting change goes out, the old ones go */
    CHECK_INT(xpol_publish(), 1);
    xpol_stats(&gen, &keys, &pending);
    CHECK_INT((int)pending, 1); /* the one just replaced: nobody holds it, the next call frees it */
    CHECK_INT(xpol_publish(), 0);
    xpol_stats(&gen, &keys, &pending);
    CHECK_INT((int)pending, 0);
    s = xpol_enter(0);
    CHECK_INT(xpol_state(s, "k5"), XPOL_IMPAIRED);
    xpol_leave(0);
    CHECK_INT(xpol_publish(), 0);
    xpol_free();
    CHECK(xpol_enter(0) == NULL);
}

#  ifndef _WIN32
#    include "plat.h"

/* readers on threads look up keys while the writer changes them (no lock;
 * ThreadSanitizer and ASan watch the snapshots' lifetimes) */
#    define PT_READERS 3
#    define PT_ROUNDS 3000
static volatile int pt_stop;
static volatile int pt_seen[PT_READERS];

static void pt_reader(void *arg)
{
    unsigned r = (unsigned)(size_t)arg;
    while (!atomic_load_int(&pt_stop)) {
        const xpol_snap *s = xpol_enter(r);
        /* "even" is impaired from the first round on: every snapshot has it */
        if (xpol_state(s, "even") == XPOL_IMPAIRED)
            atomic_fetch_add_int(&pt_seen[r], 1);
        xpol_leave(r);
    }
}

TEST(pol_threads)
{
    plat_thread_t t[PT_READERS];
    int ok = 1;
    xpol_init(PT_READERS);
    xpol_set("even", XPOL_IMPAIRED);
    xpol_publish();
    pt_stop = 0;
    for (int i = 0; i < PT_READERS; i++)
        atomic_store_int(&pt_seen[i], 0);
    for (int i = 0; i < PT_READERS; i++)
        CHECK_INT(plat_thread_start(&t[i], pt_reader, (void *)(size_t)i), 0);
    /* PT_ROUNDS at least, and on until every reader has run (a busy
     * runner may start a thread late), 30 s at most */
    {
        uint64_t end = plat_now_ms() + 30000;
        for (int i = 0;; i++) {
            char key[32];
            int all = 1;
            snprintf(key, sizeof(key), "k%d", i % 50);
            xpol_set(key, i % 2 ? XPOL_IMPAIRED : XPOL_HEALTHY);
            xpol_publish();
            for (int r = 0; r < PT_READERS; r++)
                all &= atomic_load_int(&pt_seen[r]) > 0;
            if ((i >= PT_ROUNDS && all) || plat_now_ms() > end)
                break;
        }
    }
    atomic_store_int(&pt_stop, 1);
    for (int i = 0; i < PT_READERS; i++)
        plat_thread_join(t[i]);
    for (int i = 0; i < PT_READERS; i++)
        ok &= pt_seen[i] > 0;
    CHECK(ok);
    xpol_free();
}
#  endif

/* ---- the rules and the option ---- */

static int fw_args(const char *o1, const char *v1, int windows, fw_config *c, sbuf *err)
{
    static const optdef defs[] = {EXT_OPT, EXT_FW_OPTS, {NULL, 0, 0, NULL, NULL}};
    const char *argv[4] = {"--ext"};
    int argc = 1, r;
    args_t a;
    char e[128];
    char *owned = NULL;
    const char *save = NULL;
    if (o1)
        argv[argc++] = o1;
    if (v1)
        argv[argc++] = v1;
    if (args_parse(&a, argc, (char **)argv, defs, e, sizeof(e)) < 0)
        return -2;
    r = xfw_parse(&a, windows, c, &owned, &save, err);
    free(owned);
    args_free(&a);
    return r;
}

static size_t count(const char *s, const char *sub)
{
    size_t n = 0;
    for (const char *p = s; (p = strstr(p, sub)) != NULL; p++)
        n++;
    return n;
}

TEST(surg_rules)
{
    fw_config c;
    sbuf s, err;
    sb_init(&s);
    sb_init(&err);
    fw_config_default(&c);
    CHECK_INT(fw_args(NULL, NULL, 0, &c, &err), 0);
    CHECK_INT((int)c.healthy_mark, (int)XFW_HEALTHY_MARK);
    CHECK_INT(fw_args(NULL, NULL, 1, &c, &err), 0); /* Windows: no rules to pass by */
    CHECK_INT((int)c.healthy_mark, 0);
    CHECK_INT(fw_args("--ext-healthy-mark", "0", 0, &c, &err), 0);
    CHECK_INT((int)c.healthy_mark, 0);
    CHECK_INT(fw_args("--ext-healthy-mark", "0x800", 0, &c, &err), 0);
    CHECK_INT((int)c.healthy_mark, 0x800);
    CHECK_INT(fw_args("--ext-healthy-mark", "x", 0, &c, &err), -1);
    CHECK(strstr(err.data, "bad --ext-healthy-mark") != NULL);
    sb_reset(&err);
    CHECK_INT(fw_args("--ext-healthy-mark", "0x20000000", 0, &c, &err), -1); /* the engine's own mark */
    CHECK(strstr(err.data, "shares bits with --mark") != NULL);
    sb_reset(&err);
    CHECK_INT(fw_args("--ext-healthy-mark", "0x800", 1, &c, &err), -1);
    CHECK(strstr(err.data, "Linux only") != NULL);
    sb_reset(&err);
    fw_config_default(&c);
    c.forward = 1;
    CHECK_INT(fw_args(NULL, NULL, 0, &c, &err), 0); /* a router's forwarding: no */
    CHECK_INT((int)c.healthy_mark, 0);

    fw_config_default(&c);
    c.ipv6 = 0;
    c.healthy_mark = 0x10000000;
    ports_parse("443", &c.ports);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT((int)count(s.data, "-m mark --mark 0x10000000/0x10000000 -j CONNMARK --or-mark 0x10000000\n"), 2);
    CHECK_INT((int)count(s.data, "-m mark --mark 0x10000000/0x10000000 -j MARK --and-mark 0xefffffff\n"), 2);
    CHECK_INT((int)count(s.data, "-m connmark --mark 0x10000000/0x10000000 -j RETURN\n"), 2);
    /* before the queue rules */
    CHECK(strstr(s.data, "connmark --mark 0x10000000/0x10000000 -j RETURN") < strstr(s.data, "-j NFQUEUE"));
    sb_reset(&s);
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT((int)count(s.data, "meta mark & 0x10000000 == 0x10000000 ct mark set ct mark or 0x10000000 "
                                 "meta mark set meta mark and 0xefffffff return\n"),
              2);
    CHECK_INT((int)count(s.data, "ct mark & 0x10000000 == 0x10000000 return\n"), 2);
    CHECK(strstr(s.data, "ct mark & 0x10000000 == 0x10000000 return") < strstr(s.data, "queue num"));
    /* --ext-auto's chains skip the second pass */
    sb_reset(&s);
    c.obs = 1, c.obs_group = 310, c.obs_first = 16;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT((int)count(s.data, "meta mark & 0x10000000 == 0x10000000 return\n"), 2);
    sb_reset(&s);
    fw_script(&c, FW_IPTABLES, 1, &s);
    CHECK_INT((int)count(s.data, "-m mark --mark 0x10000000/0x10000000 -j RETURN\n"), 2);
    /* the flowtable takes the connections the queue is done with */
    sb_reset(&s);
    c.obs = 0;
    c.offload = 1;
    c.iface = "wan";
    c.lan[0] = "lan";
    c.nlan = 1;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT((int)count(s.data, "ct mark & 0x10000000 == 0x10000000 flow add @ft\n"), 1);
    /* off: the rules as before */
    sb_reset(&s);
    c.healthy_mark = 0;
    fw_script(&c, FW_NFT, 1, &s);
    CHECK_INT((int)count(s.data, "0x10000000"), 0);
    sb_free(&s);
    sb_free(&err);
}

/* ---- the decision ---- */

static struct {
    int healthy, verdicts;
} slog;

static int s_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    slog.verdicts++;
    return 0;
}

static int s_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len) { return 0; }

static void s_healthy(eng_worker *w, const void *pctx) { slog.healthy++; }

static const backend sbe = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, s_verdict, s_inject, 0, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, s_healthy,
};

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* client 10.0.0.1:port <-> 10.0.0.2:80 */
static void pkt(engine *e, int c2s, unsigned port, unsigned flags, uint32_t seq, uint32_t ack, const char *d)
{
    uint8_t b[600], *t = b + 20;
    size_t dl = d ? strlen(d) : 0;
    uint32_t id = 1;
    memset(b, 0, 40);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(40 + dl));
    b[8] = 64;
    b[9] = 6;
    b[12] = 10, b[15] = c2s ? 1 : 2;
    b[16] = 10, b[19] = c2s ? 2 : 1;
    put16(t, c2s ? port : 80);
    put16(t + 2, c2s ? 80 : port);
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = 5 << 4;
    t[13] = (uint8_t)flags;
    put16(t + 14, 64000);
    if (dl)
        memcpy(t + 20, d, dl);
    engine_packet(&e->w[0], b, 40 + dl, c2s ? DIR_OUT : DIR_IN, &id);
}

#  define GET "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"

/* one connection of client port: handshake, request, two replies. Returns
 * the backend's healthy calls it made */
static int conn(engine *e, unsigned port)
{
    int before = slog.healthy;
    pkt(e, 1, port, 0x02, 1000, 0, NULL);
    pkt(e, 0, port, 0x12, 5000, 1001, NULL);
    pkt(e, 1, port, 0x10, 1001, 5001, NULL);
    pkt(e, 1, port, 0x18, 1001, 5001, GET);
    pkt(e, 0, port, 0x18, 5001, 1001 + (uint32_t)strlen(GET), "HTTP/1.1 200 OK\r\n\r\n");
    pkt(e, 0, port, 0x18, 5020, 1001 + (uint32_t)strlen(GET), "more");
    return slog.healthy - before;
}

static int setup(engine *e, engine_opts *o, const char **argv, const char *st)
{
    static const optdef defs[] = {{"strategy", 's', 1, "S", ""}, EXT_OPT, EXT_PROFILE_OPTS,
                                  {NULL, 0, 0, NULL, NULL}};
    args_t a;
    char err[128];
    int argc = 0;
    sbuf se;
    while (argv[argc])
        argc++;
    if (args_parse(&a, argc, (char **)argv, defs, err, sizeof(err)) < 0)
        return -1;
    if (ext_parse_args(&a, "test") < 0) {
        args_free(&a);
        return -1;
    }
    args_free(&a);
    engine_opts_default(o);
    o->ext = ext_engine_hooks();
    o->fw.healthy_mark = XFW_HEALTHY_MARK;
    memset(e, 0, sizeof(*e));
    e->o = o;
    e->be = &sbe;
    plat_mutex_init(&e->lock);
    sb_init(&se);
    e->st = strategy_parse(st, &se);
    sb_free(&se);
    if (!e->st || engine_workers_init(e, 1, &se) < 0)
        return -1;
    memset(&slog, 0, sizeof(slog));
    return 0;
}

static void teardown(engine *e)
{
    engine_workers_free(e);
    strategy_free(e->st);
    plat_mutex_destroy(&e->lock);
    ext_deactivate();
}

TEST(surg_decision)
{
    engine e;
    engine_opts o;

    t_current = "surgical: a plain strategy never lets go";
    {
        const char *v[] = {"--ext", NULL};
        CHECK_INT(setup(&e, &o, v, "[TCP:flags:PA]-duplicate-| \\/"), 0);
        CHECK_INT(conn(&e, 40001), 0);
        CHECK_INT((int)e.w[0].c.healthy, 0);
        teardown(&e);
    }

    t_current = "surgical: every tree cut off";
    {
        const char *v[] = {"--ext", NULL};
        CHECK_INT(setup(&e, &o, v, "[FLOW:n:1-2]-duplicate-| \\/"), 0);
        /* the third client packet (the request) cuts the only tree off;
         * from then on each packet that still comes (the two replies, no
         * forest for them) marks the connection again (counted once) */
        CHECK_INT(conn(&e, 40002), 2);
        CHECK_INT((int)e.w[0].c.healthy, 1);
        /* more of it (a connection without conntrack comes back after
         * each repeat): 4 marks in all, then plain verdicts */
        for (int i = 0; i < 5; i++)
            pkt(&e, 0, 40002, 0x18, 5024 + (uint32_t)i * 4, 1001 + (uint32_t)strlen(GET), "more");
        CHECK_INT(slog.healthy, 4);
        e.paused = 1; /* paused: nothing decided */
        CHECK_INT(conn(&e, 40003), 0);
        teardown(&e);
    }

    t_current = "surgical: a profile without a strategy, once the host is known";
    {
        const char *v[] = {"--ext", "--filter-tcp", "443", "--new", "--filter-tcp", "80", "--filter-l7", "http", NULL};
        int n;
        CHECK_INT(setup(&e, &o, v, "[TCP:flags:PA]-duplicate-| \\/"), 0);
        n = conn(&e, 40004);
        CHECK_INT(n, 3); /* the request and the two replies, not the handshake */
        CHECK_INT((int)e.w[0].c.healthy, 1);
        teardown(&e);
    }

    t_current = "surgical: not while an autolist watches";
    {
        char f[64];
        snprintf(f, sizeof(f), "geneva-test-surg-%d.txt", (int)((size_t)&e % 100000));
        remove(f);
        {
            const char *v[] = {"--ext", "--filter-tcp", "443", "--new", "--filter-tcp", "80", "--hostlist-auto", f,
                               NULL};
            CHECK_INT(setup(&e, &o, v, "[TCP:flags:PA]-duplicate-| \\/"), 0);
            CHECK_INT(conn(&e, 40005), 0);
            teardown(&e);
        }
        remove(f);
    }

    t_current = "surgical: not for a key the policy has impaired";
    {
        const char *v[] = {"--ext", NULL};
        CHECK_INT(setup(&e, &o, v, "[FLOW:n:1-2]-duplicate-| \\/"), 0);
        xpol_set("10.0.0.2", XPOL_IMPAIRED);
        xpol_publish();
        CHECK_INT(conn(&e, 40006), 0);
        xpol_set("10.0.0.2", XPOL_HEALTHY);
        xpol_set("tcp/80", XPOL_IMPAIRED);
        xpol_publish();
        CHECK_INT(conn(&e, 40007), 0);
        xpol_set("tcp/80", XPOL_HEALTHY);
        xpol_publish();
        CHECK_INT(conn(&e, 40008), 2);
        teardown(&e);
    }

    t_current = "surgical: off without the mark";
    {
        const char *v[] = {"--ext", NULL};
        CHECK_INT(setup(&e, &o, v, "[FLOW:n:1-2]-duplicate-| \\/"), 0);
        o.fw.healthy_mark = 0;
        CHECK_INT(conn(&e, 40009), 0);
        teardown(&e);
    }
}

void suite_surgical(void);
void suite_surgical(void)
{
    RUN(pol_snapshots);
#  ifndef _WIN32
    RUN(pol_threads);
#  endif
    RUN(surg_rules);
    RUN(surg_decision);
}

#else
void suite_surgical(void);
void suite_surgical(void) {}
#endif
