/* The tuner of --ext (X11a, src/ext/tuner.c): zapret2's circular as the rr
 * selector over a profile's arms, its key, its detectors and its state
 * file; and the engine running the arm of each flow's key. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine_int.h"
#include "ext_opt.h"
#include "pkt.h"
#include "plat.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ext.h"
#  include "ext/tuner.h"

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* client 10.0.0.1:port <-> 10.0.0.2:sport; the bytes into b */
static size_t mk(uint8_t *b, int c2s, unsigned port, unsigned sport, unsigned flags, uint32_t seq, uint32_t ack,
                 const char *d)
{
    uint8_t *t = b + 20;
    size_t dl = d ? strlen(d) : 0;
    memset(b, 0, 40);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(40 + dl));
    b[8] = 64;
    b[9] = 6;
    b[12] = 10, b[15] = c2s ? 1 : 2;
    b[16] = 10, b[19] = c2s ? 2 : 1;
    put16(t, c2s ? port : sport);
    put16(t + 2, c2s ? sport : port);
    put32(t + 4, seq);
    put32(t + 8, ack);
    t[12] = 5 << 4;
    t[13] = (uint8_t)flags;
    put16(t + 14, 64000);
    if (dl)
        memcpy(t + 20, d, dl);
    return 40 + dl;
}

/* ---- the tuner alone, on flows of its own conntrack ---- */

static xtune *mktune(const char *args, int narms)
{
    xtune *t = NULL;
    sbuf e;
    sb_init(&e);
    for (int i = 0; i < narms; i++)
        xtune_add_arm(&t, "\\/");
    if (args && xtune_set(&t, args, &e) < 0)
        printf("    %s\n", e.data);
    if (xtune_finish(t, 1, &e) < 0)
        printf("    %s\n", e.data);
    sb_free(&e);
    return t;
}

typedef struct {
    ctrack *ct;
    xtune *t;
    uint64_t now;
    int arm; /* the last step's */
} tctx;

static void step(tctx *c, int c2s, unsigned port, unsigned flags, uint32_t seq, uint32_t ack, const char *d)
{
    uint8_t b[1500];
    size_t n = mk(b, c2s, port, 80, flags, seq, ack, d);
    gpkt *p = pkt_parse(b, n);
    xtune_pkt k;
    int rev = 0;
    memset(&k, 0, sizeof(k));
    k.p = p;
    k.f = ctrack_feed(c->ct, p, c->now, &rev);
    k.reverse = rev;
    k.http_reply = !c2s && d && !strncmp(d, "HTTP/1.", 7);
    k.now_ms = c->now;
    c->arm = xtune_packet(c->t, &k);
    pkt_free(p);
}

/* a connection whose request the server answers with a RST (a failure) */
static int conn_rst(tctx *c, unsigned port)
{
    step(c, 1, port, 0x02, 1000, 0, NULL);
    step(c, 0, port, 0x12, 5000, 1001, NULL);
    step(c, 1, port, 0x18, 1001, 5001, "GET / HTTP/1.1\r\n\r\n");
    step(c, 0, port, 0x04, 5001, 0, NULL);
    return c->arm;
}

/* a connection whose server sends past inseq (a success) */
static int conn_ok(tctx *c, unsigned port)
{
    static char big[1300];
    memset(big, 'x', sizeof(big) - 1);
    step(c, 1, port, 0x02, 1000, 0, NULL);
    step(c, 0, port, 0x12, 5000, 1001, NULL);
    step(c, 1, port, 0x18, 1001, 5001, "GET / HTTP/1.1\r\n\r\n");
    for (uint32_t s = 5001; s < 5001 + 5 * 1299; s += 1299)
        step(c, 0, port, 0x10, s, 1019, big);
    return c->arm;
}

TEST(tune_args)
{
    xtune *t = NULL;
    sbuf e;
    sb_init(&e);
    CHECK_INT(xtune_set(&t, "rr:fails=2:time=30:final=2:key=k:nld=2:reqhost:maxseq=100:inseq=10:retrans=2:"
                            "udp_out=3:udp_in=0:no_rst:no_http_redirect:reset",
                        &e),
              0);
    CHECK_INT(xtune_finish(t, 1, &e), -1); /* no arms */
    CHECK(strstr(e.data, "needs arms") != NULL);
    xtune_add_arm(&t, "\\/");
    sb_reset(&e);
    CHECK_INT(xtune_finish(t, 1, &e), -1); /* final=2 of 1 */
    CHECK(strstr(e.data, "final=2") != NULL);
    xtune_add_arm(&t, "[TCP:flags:PA]-duplicate-| \\/");
    sb_reset(&e);
    CHECK_INT(xtune_finish(t, 1, &e), 0);
    CHECK_INT((int)xtune_arms(t), 2);
    CHECK(xtune_arm(t, 1) != NULL);
    CHECK(xtune_arm(t, 2) == NULL);
    sb_reset(&e);
    CHECK_INT(xtune_set(&t, "rr", &e), -1); /* once */
    xtune_free(t);
    t = NULL;
    sb_reset(&e);
    CHECK_INT(xtune_set(&t, "ts", &e), -1);
    xtune_free(t);
    t = NULL;
    sb_reset(&e);
    CHECK_INT(xtune_set(&t, "rr:fails=0", &e), -1);
    CHECK(strstr(e.data, "fails=0") != NULL);
    xtune_free(t);
    t = NULL;
    sb_reset(&e);
    CHECK_INT(xtune_set(&t, "rr:key=a/b", &e), -1);
    xtune_free(t);
    t = NULL;
    sb_reset(&e);
    CHECK_INT(xtune_set(&t, "rr:reset=1", &e), -1);
    xtune_free(t);
    t = NULL;
    xtune_add_arm(&t, "[x");
    sb_reset(&e);
    CHECK_INT(xtune_finish(t, 1, &e), -1);
    CHECK(strstr(e.data, "--ext-arm 1") != NULL);
    xtune_free(t);
    sb_free(&e);
}

TEST(tune_rr)
{
    tctx c;
    ct_config cc;
    char k[300];
    ct_config_default(&cc);
    memset(&c, 0, sizeof(c));
    c.ct = ctrack_new(&cc);
    c.now = 1000000;
    xtune_start(NULL, NULL);

    t_current = "rr: fails failures rotate, after the last arm 1 again";
    c.t = mktune("rr:fails=2", 3);
    CHECK_INT(conn_rst(&c, 40001), 0);
    CHECK_INT(conn_rst(&c, 40002), 1); /* the second failure: arm 2 */
    CHECK_INT(conn_rst(&c, 40003), 1);
    CHECK_INT(conn_rst(&c, 40004), 2);
    CHECK_INT(conn_rst(&c, 40005), 2);
    CHECK_INT(conn_rst(&c, 40006), 0);
    /* one count per connection: more RSTs of the same one do not count */
    step(&c, 0, 40006, 0x04, 5001, 0, NULL);
    step(&c, 0, 40006, 0x04, 5001, 0, NULL);
    CHECK_INT(c.arm, 0);
    /* a success resets the count */
    CHECK_INT(conn_rst(&c, 40007), 0);
    CHECK_INT(conn_ok(&c, 40008), 0);
    CHECK_INT(conn_rst(&c, 40009), 0);
    CHECK_INT(conn_rst(&c, 40010), 1);
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: time between failures";
    c.t = mktune("rr:fails=2:time=60", 2);
    CHECK_INT(conn_rst(&c, 40011), 0);
    c.now += 61000; /* too late: the count starts again */
    CHECK_INT(conn_rst(&c, 40012), 0);
    c.now += 60000; /* in time */
    CHECK_INT(conn_rst(&c, 40013), 1);
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: final stops the rotation";
    c.t = mktune("rr:fails=1:final=2", 3);
    CHECK_INT(conn_rst(&c, 40014), 1);
    CHECK_INT(conn_rst(&c, 40015), 1);
    CHECK_INT(conn_rst(&c, 40016), 1);
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: the client's retransmissions";
    c.t = mktune("rr:fails=1:retrans=3", 2);
    step(&c, 1, 40017, 0x02, 1000, 0, NULL);
    step(&c, 0, 40017, 0x12, 5000, 1001, NULL);
    for (int i = 0; i < 3; i++)
        step(&c, 1, 40017, 0x18, 1001, 5001, "GET / HTTP/1.1\r\n\r\n");
    CHECK_INT(c.arm, 0); /* the first send and two retransmissions */
    step(&c, 1, 40017, 0x18, 1001, 5001, "GET / HTTP/1.1\r\n\r\n");
    CHECK_INT(c.arm, 1);
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: no_rst";
    c.t = mktune("rr:fails=1:no_rst", 2);
    CHECK_INT(conn_rst(&c, 40018), 0);
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: an HTTP redirect to another domain";
    c.t = mktune("rr:fails=1", 2);
    {
        ct_flow *f;
        int rev;
        uint8_t b[600];
        size_t n;
        gpkt *p;
        step(&c, 1, 40019, 0x02, 1000, 0, NULL);
        /* the flow's host as the L7 found it */
        n = mk(b, 1, 40019, 80, 0x10, 1001, 5001, NULL);
        p = pkt_parse(b, n);
        f = ctrack_feed(c.ct, p, c.now, &rev);
        pkt_free(p);
        free(f->chost);
        f->chost = xstrdup("a.example.com");
        step(&c, 0, 40019, 0x18, 5001, 1001, "HTTP/1.1 302 Found\r\nLocation: http://block.example.net/\r\n\r\n");
        CHECK_INT(c.arm, 1);
        /* the key is the host's */
        CHECK_INT(xtune_hostkey(c.t, f, k, sizeof(k)), 1);
        CHECK_STR(k, "a.example.com");
        free(f->chost); /* the engine's flow hook frees it, not ctrack */
        f->chost = NULL;
    }
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: UDP";
    c.t = mktune("rr:fails=1:udp_out=3:udp_in=0", 2);
    {
        uint8_t b[64];
        for (int i = 0; i < 3; i++) {
            gpkt *p;
            xtune_pkt kk;
            int rev = 0;
            memset(b, 0, sizeof(b));
            b[0] = 0x45;
            put16(b + 2, 28 + 4);
            b[8] = 64;
            b[9] = 17;
            b[12] = 10, b[15] = 1;
            b[16] = 10, b[19] = 2;
            put16(b + 20, 50000);
            put16(b + 22, 443);
            put16(b + 24, 12);
            p = pkt_parse(b, 32);
            memset(&kk, 0, sizeof(kk));
            kk.p = p;
            kk.f = ctrack_feed(c.ct, p, c.now, &rev);
            kk.reverse = rev;
            kk.now_ms = c.now;
            c.arm = xtune_packet(c.t, &kk);
            pkt_free(p);
        }
        CHECK_INT(c.arm, 1);
    }
    xtune_free(c.t);
    xtune_reset();

    t_current = "rr: the key";
    c.t = mktune("rr:nld=2", 2);
    {
        ct_flow f;
        memset(&f, 0, sizeof(f));
        f.ver = 4;
        f.srv[0] = 10, f.srv[3] = 2;
        CHECK_INT(xtune_hostkey(c.t, &f, k, sizeof(k)), 1);
        CHECK_STR(k, "10.0.0.2");
        free(f.chost);
        f.chost = xstrdup("static.intranet.microsoft.com");
        CHECK_INT(xtune_hostkey(c.t, &f, k, sizeof(k)), 1);
        CHECK_STR(k, "microsoft.com");
        free(f.chost);
        f.chost = xstrdup("localhost");
        CHECK_INT(xtune_hostkey(c.t, &f, k, sizeof(k)), 1);
        CHECK_STR(k, "localhost"); /* no second level: as it is */
        xtune_free(c.t);
        c.t = mktune("rr:reqhost", 2);
        free(f.chost);
        f.chost = NULL;
        CHECK_INT(xtune_hostkey(c.t, &f, k, sizeof(k)), 0);
        CHECK_INT(xtune_current(c.t, &f), -1);
    }
    xtune_free(c.t);
    xtune_stop();
    ctrack_free(c.ct);
}

TEST(tune_state)
{
    tctx c;
    ct_config cc;
    sbuf e;
    char path[80];
    char *d;
    size_t n;
    snprintf(path, sizeof(path), "geneva-test-tune-%d.jsonl", (int)plat_getpid());
    remove(path);
    ct_config_default(&cc);
    memset(&c, 0, sizeof(c));
    c.ct = ctrack_new(&cc);
    c.now = 1000000;
    sb_init(&e);
    CHECK_INT(xtune_start(path, &e), 0);
    c.t = mktune("rr:fails=1", 3);
    CHECK_INT(conn_rst(&c, 40101), 1);
    xtune_tick(c.now); /* written now */
    d = read_file(path, &n);
    CHECK(d && strstr(d, "\"key\":\"p1/10.0.0.2\",\"arm\":2") != NULL);
    free(d);
    CHECK_INT(conn_rst(&c, 40102), 2);
    xtune_stop(); /* and at the end */
    CHECK_INT(xtune_start(path, &e), 0);
    CHECK_INT(conn_ok(&c, 40103), 2);
    xtune_stop();
    /* a state of more arms than the profile has: arm 1 */
    xtune_free(c.t);
    c.t = mktune("rr:fails=1", 2);
    CHECK_INT(xtune_start(path, &e), 0);
    CHECK_INT(conn_ok(&c, 40104), 0);
    xtune_stop();
    remove(path);
    /* a file that cannot be written */
    CHECK_INT(xtune_start("/nonexistent-dir/x/state", &e), -1);
    CHECK(strstr(e.data, "cannot write") != NULL);
    xtune_free(c.t);
    ctrack_free(c.ct);
    sb_free(&e);
}

/* ---- in the engine ---- */

static struct {
    int verdicts, injects;
} tlog;

static int t_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    tlog.verdicts++;
    return 0;
}

static int t_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    tlog.injects++;
    return 0;
}

static const backend tbe = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, t_verdict, t_inject, 0, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
};

static void epkt(engine *e, int c2s, unsigned port, unsigned flags, uint32_t seq, uint32_t ack, const char *d)
{
    uint8_t b[600];
    uint32_t id = 1;
    size_t n = mk(b, c2s, port, 80, flags, seq, ack, d);
    engine_packet(&e->w[0], b, n, c2s ? DIR_OUT : DIR_IN, &id);
}

#  define GET "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"

/* a connection the server resets after the request; the injects it made
 * (the duplicate of arm 2) */
static int econn(engine *e, unsigned port)
{
    int before = tlog.injects;
    epkt(e, 1, port, 0x02, 1000, 0, NULL);
    epkt(e, 0, port, 0x12, 5000, 1001, NULL);
    epkt(e, 1, port, 0x10, 1001, 5001, NULL);
    epkt(e, 1, port, 0x18, 1001, 5001, GET);
    epkt(e, 0, port, 0x14, 5001, 1001 + (uint32_t)strlen(GET), NULL);
    return tlog.injects - before;
}

TEST(tune_engine)
{
    static const optdef defs[] = {{"strategy", 's', 1, "S", ""}, EXT_OPT, EXT_PROFILE_OPTS,
                                  {NULL, 0, 0, NULL, NULL}};
    const char *argv[] = {"--ext", "--filter-tcp", "80", "--ext-arm", "\\/", "--ext-arm",
                          "[TCP:flags:PA]-duplicate-| \\/", "--ext-tune", "rr:fails=2:final=2", NULL};
    engine e;
    engine_opts o;
    args_t a;
    char err[128];
    sbuf se;
    CHECK_INT(args_parse(&a, 9, (char **)argv, defs, err, sizeof(err)), 0);
    CHECK_INT(ext_parse_args(&a, "test"), 0);
    args_free(&a);
    engine_opts_default(&o);
    o.ext = ext_engine_hooks();
    memset(&e, 0, sizeof(e));
    e.o = &o;
    e.be = &tbe;
    plat_mutex_init(&e.lock);
    sb_init(&se);
    e.st = strategy_parse("\\/", &se);
    CHECK_INT(engine_workers_init(&e, 1, &se), 0);
    sb_free(&se);
    memset(&tlog, 0, sizeof(tlog));
    /* arm 1 (nothing) for the host's key until two connections failed */
    CHECK_INT(econn(&e, 41001), 0);
    CHECK_INT(econn(&e, 41002), 0);
    /* then arm 2: the request duplicated, and final: it stays */
    CHECK_INT(econn(&e, 41003), 1);
    CHECK_INT(econn(&e, 41004), 1);
    CHECK_INT(econn(&e, 41005), 1);
    {
        sbuf s;
        jw w;
        sb_init(&s);
        jw_init(&w, &s);
        jw_obj(&w);
        xtune_keys(&w, 10);
        jw_obj_end(&w);
        CHECK(strstr(s.data, "\"key\":\"p1/a.example\",\"arm\":2") != NULL);
        sb_free(&s);
    }
    engine_workers_free(&e);
    strategy_free(e.st);
    plat_mutex_destroy(&e.lock);
    ext_deactivate();
}

void suite_tuner(void);
void suite_tuner(void)
{
    RUN(tune_args);
    RUN(tune_rr);
    RUN(tune_state);
    RUN(tune_engine);
}

#else
void suite_tuner(void);
void suite_tuner(void) {}
#endif
