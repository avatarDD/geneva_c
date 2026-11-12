/* Stage X6c: the IP cache (src/ext/ipcache.c), the autolist
 * (src/ext/autolist.c, zapret2's --hostlist-auto) and both in the choice of
 * the profile per packet (src/ext/ext.c). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "pkt.h"
#include "plat.h"
#include "strategy.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/autolist.h"
#  include "ext/ext.h"
#  include "ext/ipcache.h"
#  include "ext/lists.h"
#  include "ext/profile.h"

static void put16(uint8_t *p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, v >> 16);
    put16(p + 2, v & 0xffff);
}

static const char *tmp(const char *tag)
{
    static char path[4][80];
    static int k;
    char *p = path[k++ & 3];
    snprintf(p, 80, "geneva-test-ah-%d-%s", (int)plat_getpid(), tag);
    return p;
}

static char *slurp(const char *path)
{
    size_t n;
    char *d = read_file(path, &n);
    return d ? d : xstrdup("");
}

/* ---- the IP cache ------------------------------------------------------------- */

static const uint8_t A1[4] = {93, 184, 216, 34}, A2[4] = {1, 2, 3, 4};

TEST(ah_ipcache)
{
    static const uint8_t v6[16] = {0x2a, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    char h[64];
    int ip = 7;
    xipc_reset();
    /* host names only with --ext-ipcache-hostname */
    xipc_put_host(4, A1, "a.com", 0, 1000);
    CHECK_INT(xipc_get_host(4, A1, h, sizeof(h), &ip), 0);
    CHECK_INT((int)xipc_count(), 0);
    xipc_config(10, 1);
    CHECK(xipc_hostname_on());
    xipc_put_host(4, A1, "a.com", 0, 1000);
    xipc_put_host(6, v6, "[2a00::1]", 1, 1000);
    CHECK_INT(xipc_get_host(4, A1, h, sizeof(h), &ip), 1);
    CHECK_STR(h, "a.com");
    CHECK_INT(ip, 0);
    CHECK_INT(xipc_get_host(6, v6, h, sizeof(h), &ip), 1);
    CHECK_INT(ip, 1);
    CHECK_INT(xipc_get_host(4, A2, h, sizeof(h), &ip), 0);
    /* a short buffer: the name cut, not overrun */
    CHECK_INT(xipc_get_host(4, A1, h, 3, &ip), 1);
    CHECK_STR(h, "a.");
    /* TTLs per interface, apart from the names */
    xipc_put_ttl(4, A1, "eth0", 52, 1000);
    xipc_put_ttl(4, A1, NULL, 60, 1000);
    CHECK_INT(xipc_get_ttl(4, A1, "eth0"), 52);
    CHECK_INT(xipc_get_ttl(4, A1, NULL), 60);
    CHECK_INT(xipc_get_ttl(4, A1, ""), 60);
    CHECK_INT(xipc_get_ttl(4, A1, "eth1"), 0);
    CHECK_INT(xipc_get_ttl(4, A2, NULL), 0);
    CHECK_INT((int)xipc_count(), 3);
    /* the lifetime counts from the last write */
    xipc_put_ttl(4, A1, "eth0", 52, 8000);
    xipc_purge(11500);
    CHECK_INT((int)xipc_count(), 1);
    CHECK_INT(xipc_get_ttl(4, A1, "eth0"), 52);
    xipc_purge(11700); /* once a second at most */
    xipc_purge(19000);
    CHECK_INT((int)xipc_count(), 0);
    /* 0: for ever */
    xipc_config(0, 1);
    xipc_put_host(4, A2, "b.com", 0, 1000);
    xipc_purge(1000000000);
    CHECK_INT((int)xipc_count(), 1);
    xipc_reset();
    CHECK_INT((int)xipc_count(), 0);
    CHECK(!xipc_hostname_on());
    {
        /* the table grows: every entry stays found */
        uint8_t a[4] = {10, 0, 0, 0};
        int bad = 0;
        for (unsigned k = 0; k < 5000; k++) {
            a[2] = (uint8_t)(k >> 8), a[3] = (uint8_t)k;
            xipc_put_ttl(4, a, k & 1 ? "wan" : NULL, (uint8_t)(k % 200 + 1), 1000);
        }
        CHECK_INT((int)xipc_count(), 5000);
        for (unsigned k = 0; k < 5000; k++) {
            a[2] = (uint8_t)(k >> 8), a[3] = (uint8_t)k;
            bad += xipc_get_ttl(4, a, k & 1 ? "wan" : NULL) != (uint8_t)(k % 200 + 1);
        }
        CHECK_INT(bad, 0);
        xipc_reset();
    }
}

/* A DNS answer for name: A 1.2.3.4 and AAAA 2a00::1, the names compressed */
static size_t dns_answer(uint8_t *b, const char *name, int qtype)
{
    size_t n = 12;
    const char *s = name;
    memset(b, 0, 12);
    put16(b, 0x1234);
    put16(b + 2, 0x8180);
    put16(b + 4, 1);
    put16(b + 6, 3);
    while (*s) {
        const char *e = strchr(s, '.');
        size_t l = e ? (size_t)(e - s) : strlen(s);
        b[n++] = (uint8_t)l;
        memcpy(b + n, s, l);
        n += l;
        s += l + (e ? 1 : 0);
    }
    b[n++] = 0;
    put16(b + n, (unsigned)qtype);
    put16(b + n + 2, 1);
    n += 4;
    /* CNAME (skipped), A, AAAA */
    put16(b + n, 0xc00c);
    put16(b + n + 2, 5);
    put16(b + n + 4, 1);
    put32(b + n + 6, 60);
    put16(b + n + 10, 2);
    put16(b + n + 12, 0xc00c);
    n += 14;
    put16(b + n, 0xc00c);
    put16(b + n + 2, 1);
    put16(b + n + 4, 1);
    put32(b + n + 6, 60);
    put16(b + n + 10, 4);
    memcpy(b + n + 12, A2, 4);
    n += 16;
    put16(b + n, 0xc00c);
    put16(b + n + 2, 28);
    put16(b + n + 4, 1);
    put32(b + n + 6, 60);
    put16(b + n + 10, 16);
    memset(b + n + 12, 0, 16);
    b[n + 12] = 0x2a;
    b[n + 27] = 1;
    n += 28;
    return n;
}

TEST(ah_dns)
{
    static const uint8_t v6[16] = {0x2a, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t b[512];
    char h[64];
    size_t n;
    xipc_reset();
    n = dns_answer(b, "WWW.Example.org", 1);
    CHECK_INT(xipc_dns_response(b, n, 1000), 0); /* names are not cached */
    xipc_config(XIPC_LIFETIME, 1);
    CHECK_INT(xipc_dns_response(b, n, 1000), 2);
    CHECK_INT(xipc_get_host(4, A2, h, sizeof(h), NULL), 1);
    CHECK_STR(h, "www.example.org");
    CHECK_INT(xipc_get_host(6, v6, h, sizeof(h), NULL), 1);
    /* not an answer, no answers, another query type */
    b[2] = 0x01;
    CHECK_INT(xipc_dns_response(b, n, 1000), -1);
    b[2] = 0x81;
    n = dns_answer(b, "x.org", 16);
    CHECK_INT(xipc_dns_response(b, n, 1000), -1);
    /* every cut of an answer: no overrun (ASan), at most the whole */
    n = dns_answer(b, "cut.example.org", 28);
    for (size_t k = 0; k < n; k++) {
        uint8_t *c = xmalloc(k ? k : 1);
        memcpy(c, b, k);
        CHECK(xipc_dns_response(c, k, 1000) <= 1);
        free(c);
    }
    CHECK_INT(xipc_dns_response(b, n, 1000), 2);
    /* a pointer loop in the question */
    n = 12;
    put16(b + 4, 1);
    put16(b + 6, 1);
    put16(b + 12, 0xc00c);
    CHECK_INT(xipc_dns_response(b, 18, 1000), -1);
    xipc_reset();
}

/* ---- the autolist itself ------------------------------------------------------ */

TEST(ah_list)
{
    const char *path = tmp("auto.txt");
    xlist *l;
    xlistref r, none;
    sbuf e;
    char *d;
    sb_init(&e);
    memset(&r, 0, sizeof(r));
    memset(&none, 0, sizeof(none));
    remove(path);
    /* created when missing; never empty */
    l = xlist_auto(path, &e);
    CHECK(l != NULL);
    if (!l)
        goto out;
    xlistref_add(&r, l);
    CHECK(l->autolist);
    CHECK(xhs_search(&l->hs, "@&()", 0, NULL));
    CHECK(!xlistref_empty(&r));
    CHECK_INT(xlists_host(&r, &none, "a.com", 0, NULL), 0);
    CHECK_INT(xlist_append(l, "a.com"), 0);
    CHECK_INT(xlists_host(&r, &none, "www.a.com", 0, NULL), 1);
    d = slurp(path);
    CHECK_STR(d, "a.com\n");
    free(d);
    /* what it wrote is not read again; what others write is */
    CHECK_INT(xlists_reload(10000, 0), 0);
    write_file(path, "a.com\n!b.a.com\nc.com\n", 21);
    CHECK_INT(xlists_reload(20000, 1), 1);
    CHECK_INT(xlists_host(&r, &none, "c.com", 0, NULL), 1);
    {
        /* "!" in an autolist: excluded, not merely absent */
        int ex = 0;
        CHECK_INT(xlists_host(&r, &none, "b.a.com", 0, &ex), 0);
        CHECK_INT(ex, 1);
    }
    /* emptied: the impossible name again */
    write_file(path, "", 0);
    CHECK_INT(xlists_reload(30000, 1), 1);
    CHECK(xhs_search(&l->hs, "@&()", 0, NULL));
    xlistref_free(&r);
    /* gzip */
    write_file(path, "\x1f\x8b\x08\x00", 4);
    CHECK(xlist_auto(path, &e) == NULL);
    CHECK(strstr(e.data, "cannot be in gzip") != NULL);
out:
    remove(path);
    sb_free(&e);
    CHECK_INT((int)xlists_count(), 0);
}

static const optdef defs[] = {
    {"strategy", 's', 1, "S", ""},
    {"strategy-file", 'f', 1, "F", ""},
    EXT_OPT,
    EXT_PROFILE_OPTS,
    {NULL, 0, 0, NULL, NULL},
};

static const char *build(const char **argv, xprofiles *ps)
{
    static char buf[300];
    args_t a, a0;
    char err[128];
    sbuf e;
    int argc = 0, rc;
    while (argv[argc])
        argc++;
    memset(ps, 0, sizeof(*ps));
    if (args_parse(&a, argc, (char **)argv, defs, err, sizeof(err)) < 0) {
        snprintf(buf, sizeof(buf), "args: %s", err);
        return buf;
    }
    a0 = ext_cmd_args(&a);
    sb_init(&e);
    rc = xprof_build(&a, arg_has(&a0, "strategy") || arg_has(&a0, "strategy-file"), ps, &e);
    snprintf(buf, sizeof(buf), "%s", rc < 0 ? e.data : "OK");
    sb_free(&e);
    args_free(&a);
    return buf;
}

TEST(ah_options)
{
    const char *f1 = tmp("o1.txt"), *f2 = tmp("o2.txt");
    xprofiles ps;
    {
        const char *v[] = {"--hostlist-auto", f1, "-s", "\\/", NULL};
        xprofile *p;
        CHECK_STR(build(v, &ps), "OK");
        p = ps.v[0];
        CHECK(p->ahl != NULL);
        CHECK_INT(p->ah_fail_threshold, 3);
        CHECK_INT(p->ah_fail_time, 60);
        CHECK_INT(p->ah_retrans_threshold, 3);
        CHECK_INT((int)p->ah_retrans_maxseq, 32768);
        CHECK_INT(p->ah_retrans_reset, 1);
        CHECK_INT((int)p->ah_incoming_maxseq, 4096);
        CHECK_INT(p->ah_udp_out, 4);
        CHECK_INT(p->ah_udp_in, 1);
        CHECK(!xprof_hostlists_empty(p));
        xprof_free(&ps);
    }
    {
        /* the parameters; a template's go with --import */
        const char *v[] = {"--template=t", "--hostlist-auto", f1, "--hostlist-auto-fail-threshold", "5",
                           "--hostlist-auto-retrans-reset=0", "--new", "--import", "t",
                           "--hostlist-auto-udp-out", "0", "-s", "\\/", NULL};
        xprofile *p;
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 1);
        p = ps.v[0];
        CHECK(p->ahl != NULL);
        CHECK_INT(p->ah_fail_threshold, 5);
        CHECK_INT(p->ah_retrans_reset, 0);
        CHECK_INT(p->ah_udp_out, 0);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--hostlist-auto", f1, "--hostlist-auto-retrans-reset", "-s", "\\/", NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT(ps.v[0]->ah_retrans_reset, 1);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--hostlist-auto", f1, "--hostlist-auto", f2, "-s", "\\/", NULL};
        CHECK(strstr(build(v, &ps), "only one --hostlist-auto per profile") != NULL);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--template=t", "--hostlist-auto", f1, "--new", "--hostlist-auto", f2, "--import", "t",
                           "-s", "\\/", NULL};
        CHECK(strstr(build(v, &ps), "autohostlist replacement is not supported") != NULL);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--hostlist", f1, "--hostlist-auto", f1, "-s", "\\/", NULL};
        CHECK(strstr(build(v, &ps), "already a --hostlist of this profile") != NULL);
        xprof_free(&ps);
    }
    {
        const char *bad[][2] = {{"--hostlist-auto-fail-threshold", "21"}, {"--hostlist-auto-fail-threshold", "0"},
                                {"--hostlist-auto-fail-time", "0"},       {"--hostlist-auto-retrans-threshold", "1"},
                                {"--hostlist-auto-retrans-threshold", "11"}, {"--hostlist-auto-retrans-reset", "2"},
                                {"--hostlist-auto-udp-in", "x"}};
        for (size_t k = 0; k < sizeof(bad) / sizeof(*bad); k++) {
            char o[80];
            const char *v[] = {"--hostlist-auto", f1, o, "-s", "\\/", NULL};
            snprintf(o, sizeof(o), "%s=%s", bad[k][0], bad[k][1]);
            CHECK(strstr(build(v, &ps), "bad --hostlist-auto-") != NULL);
            xprof_free(&ps);
        }
    }
    remove(f1);
    remove(f2);
    CHECK_INT((int)xlists_count(), 0);
}

TEST(ah_counters)
{
    const char *f = tmp("c.txt"), *dbg = tmp("c.log");
    xprofiles ps;
    xprofile *p;
    char *d;
    const char *v[] = {"--hostlist-auto", f, "--hostlist-auto-fail-time", "10", "-s", "\\/", NULL};
    remove(f);
    remove(dbg);
    CHECK_STR(build(v, &ps), "OK");
    if (ps.n != 1)
        goto out;
    p = ps.v[0];
    CHECK_INT(xah_debug_log(dbg), 0);
    /* two failures, then the site works: from zero again */
    xah_failed(p, "a.com", 0, "10.0.0.2:40000", 3, 1000);
    xah_failed(p, "a.com", 0, "", 3, 2000);
    CHECK_INT((int)p->nfails, 1);
    xah_reset(p, "a.com", "", 3);
    CHECK_INT((int)p->nfails, 0);
    /* failures expire fail-time seconds after the first */
    xah_failed(p, "a.com", 0, "", 3, 1000);
    xah_failed(p, "a.com", 0, "", 3, 5000);
    xah_purge(p, 10000);
    CHECK_INT((int)p->nfails, 1);
    xah_purge(p, 10500); /* once a second at most */
    xah_purge(p, 11000);
    CHECK_INT((int)p->nfails, 0);
    /* the third within the time adds the host */
    xah_failed(p, "a.com", 0, "", 3, 20000);
    xah_failed(p, "a.com", 0, "", 3, 21000);
    xah_failed(p, "a.com", 0, "", 3, 22000);
    CHECK_INT((int)p->nfails, 0);
    CHECK(xprof_hosts(p, "www.a.com", 0, NULL));
    d = slurp(f);
    CHECK_STR(d, "a.com\n");
    free(d);
    /* a host in the list already is not added twice */
    for (int k = 0; k < 3; k++)
        xah_failed(p, "www.a.com", 0, "", 3, 30000);
    d = slurp(f);
    CHECK_STR(d, "a.com\n");
    free(d);
    xah_debug_log(NULL);
    d = slurp(dbg);
    CHECK(strstr(d, " : a.com : profile 1 (noname) : client 10.0.0.2:40000 : proto http : fail counter 1/3\n") !=
          NULL);
    CHECK(strstr(d, "a.com : profile 1 (noname) : client  : proto http : fail counter reset. website is working.") !=
          NULL);
    CHECK(strstr(d, "a.com : profile 1 (noname) : client  : proto http : adding to ") != NULL);
    CHECK(strstr(d, "www.a.com : profile 1 (noname) : client  : proto http : NOT adding, duplicate detected") !=
          NULL);
    /* "dd.mm.yyyy hh:mm:ss : " */
    CHECK(strlen(d) > 22 && d[2] == '.' && d[5] == '.' && d[10] == ' ' && d[13] == ':' && d[19] == ' ');
    free(d);
out:
    xprof_free(&ps);
    remove(f);
    remove(dbg);
    CHECK_INT((int)xlists_count(), 0);
}

/* ---- packets ------------------------------------------------------------------ */

/* TCP between 10.0.0.2:cport and 93.184.216.34:80 */
static size_t mk(uint8_t *b, unsigned cport, int in, uint8_t flags, uint32_t seq, uint32_t ack, const char *data)
{
    size_t dl = strlen(data), n = 40 + dl;
    static const uint8_t cli[4] = {10, 0, 0, 2};
    memset(b, 0, 40);
    b[0] = 0x45;
    put16(b + 2, (unsigned)n);
    b[8] = in ? 50 : 64;
    b[9] = 6;
    memcpy(b + 12, in ? A1 : cli, 4);
    memcpy(b + 16, in ? cli : A1, 4);
    put16(b + 20, in ? 80 : cport);
    put16(b + 22, in ? cport : 80);
    put32(b + 24, seq);
    put32(b + 28, ack);
    b[32] = 0x50;
    b[33] = flags;
    put16(b + 34, 65535);
    memcpy(b + 40, data, dl);
    put16(b + 10, inet_csum(b, 20, 0));
    return n;
}

TEST(ah_rst)
{
    uint8_t b[200], r[60];
    size_t n = mk(b, 40000, 0, 0x18, 1001, 5001, "GET / HTTP/1.1\r\n\r\n"), rn;
    gpkt *p = pkt_parse(b, n), *q;
    CHECK(p != NULL);
    if (!p)
        return;
    rn = xah_rst(p, NULL, r);
    CHECK_INT((int)rn, 40);
    q = pkt_parse(r, rn);
    CHECK(q != NULL);
    if (q) {
        uint8_t back[60];
        CHECK_MEM(q->src, 4, A1, 4);
        CHECK_INT(q->sport, 80);
        CHECK_INT(q->dport, 40000);
        CHECK_INT((int)q->seq, 5001);
        CHECK_INT((int)q->ack, 1001);
        CHECK_INT(q->tcpflags, 4);
        CHECK_INT(q->ttl, 64);
        /* the checksums as a rebuild computes them */
        pkt_mark_dirty(q);
        CHECK_INT((int)pkt_build(q, back, sizeof(back)), 40);
        CHECK_MEM(back, 40, r, 40);
        pkt_free(q);
    }
    pkt_free(p);
}

static void rp(void *ud, const uint8_t *raw, size_t len, strat_dir dir, unsigned piece, unsigned pieces, void *xctx)
{
    (void)ud, (void)raw, (void)len, (void)dir, (void)piece, (void)pieces, (void)xctx;
}

static strategy *go(xoffline *x, strategy *cmd, const uint8_t *b, size_t n, strat_dir dir, uint64_t t)
{
    gpkt *p = pkt_parse(b, n);
    strategy *st = cmd;
    int v;
    CHECK(p != NULL);
    if (!p)
        return NULL;
    xoff_packet(x, &st, p, dir, t, b, n, rp, NULL, &v);
    pkt_free(p);
    return st;
}

static int activate(const char **argv)
{
    args_t a;
    char err[128];
    int argc = 0, rc;
    while (argv[argc])
        argc++;
    if (args_parse(&a, argc, (char **)argv, defs, err, sizeof(err)) < 0)
        return -2;
    rc = ext_parse_args(&a, "test");
    args_free(&a);
    return rc;
}

#define REQ "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n"

/* A connection of client port cport up to the request; returns what the
 * request got */
static strategy *open_req(xoffline *x, strategy *cmd, unsigned cport, uint64_t t)
{
    uint8_t b[200];
    go(x, cmd, b, mk(b, cport, 0, 0x02, 1000, 0, ""), DIR_OUT, t);
    go(x, cmd, b, mk(b, cport, 1, 0x12, 5000, 1001, ""), DIR_IN, t + 1);
    go(x, cmd, b, mk(b, cport, 0, 0x10, 1001, 5001, ""), DIR_OUT, t + 2);
    return go(x, cmd, b, mk(b, cport, 0, 0x18, 1001, 5001, REQ), DIR_OUT, t + 3);
}

TEST(ah_flows)
{
    const char *f = tmp("flows.txt");
    const char *v[] = {"--ext", "-s", "\\/", "--filter-tcp", "80", "--hostlist-auto", f,
                       "--hostlist-auto-fail-threshold", "2", "--new", "-s", "[TCP:flags:S]-drop-| \\/", NULL};
    uint8_t b[200];
    xoffline *x = NULL;
    strategy *cmd, *st;
    sbuf e;
    char *d;
    remove(f);
    CHECK_INT(activate(v), 0);
    sb_init(&e);
    cmd = strategy_parse("\\/", &e);
    sb_free(&e);
    x = xoff_new();
    if (!x || !cmd)
        goto out;
    /* flow 1: the SYN goes by profile 2 (no host yet); the request names
     * a.com, not in the autolist: profile 1 keeps it, without a strategy */
    st = go(x, cmd, b, mk(b, 40001, 0, 0x02, 1000, 0, ""), DIR_OUT, 1000);
    CHECK(st && st != cmd);
    go(x, cmd, b, mk(b, 40001, 1, 0x12, 5000, 1001, ""), DIR_IN, 1001);
    go(x, cmd, b, mk(b, 40001, 0, 0x10, 1001, 5001, ""), DIR_OUT, 1002);
    st = go(x, cmd, b, mk(b, 40001, 0, 0x18, 1001, 5001, REQ), DIR_OUT, 1003);
    CHECK(st == NULL);
    /* three retransmissions: a failure */
    for (int k = 0; k < 3; k++)
        CHECK(go(x, cmd, b, mk(b, 40001, 0, 0x18, 1001, 5001, REQ), DIR_OUT, 1100 + (uint64_t)k) == NULL);
    d = slurp(f);
    CHECK_STR(d, "");
    free(d);
    /* flow 2: the server resets it at once: the second failure adds a.com */
    CHECK(open_req(x, cmd, 40002, 2000) == NULL);
    go(x, cmd, b, mk(b, 40002, 1, 0x14, 5001, 1031, ""), DIR_IN, 2010);
    d = slurp(f);
    CHECK_STR(d, "a.com\n");
    free(d);
    /* flow 3: a.com is in the autolist: the strategy runs */
    CHECK(open_req(x, cmd, 40003, 3000) == cmd);
    st = go(x, cmd, b, mk(b, 40003, 1, 0x18, 5001, 1031, "HTTP/1.1 200 OK\r\n\r\n"), DIR_IN, 3010);
    CHECK(st == cmd);
out:
    xoff_free(x);
    strategy_free(cmd);
    ext_reset();
    remove(f);
    CHECK_INT((int)xlists_count(), 0);
}

/* The tuner offline (apply): circular's step runs on the packets as live */
TEST(ah_tune_offline)
{
    const char *v[] = {"--ext", "--filter-tcp", "80", "--ext-arm", "\\/", "--ext-arm", "[TCP:flags:PA]-drop-| \\/",
                       "--ext-tune", "rr:fails=1", NULL};
    uint8_t b[200];
    xoffline *x = NULL;
    strategy *st;
    sbuf e;
    CHECK_INT(activate(v), 0);
    sb_init(&e);
    x = xoff_new();
    if (!x)
        goto out;
    /* flow 1 on arm 1; the server's RST at its first byte: a failure */
    st = open_req(x, NULL, 40011, 1000);
    CHECK(st != NULL);
    if (st)
        strategy_print(st, &e);
    CHECK_STR(e.data, "\\/");
    go(x, NULL, b, mk(b, 40011, 1, 0x14, 5001, 1031, ""), DIR_IN, 1010);
    /* flow 2: a.com is at arm 2 */
    sb_reset(&e);
    st = open_req(x, NULL, 40012, 2000);
    CHECK(st != NULL);
    if (st)
        strategy_print(st, &e);
    CHECK_STR(e.data, "[TCP:flags:PA]-drop-| \\/");
out:
    sb_free(&e);
    xoff_free(x);
    ext_reset();
}

/* A template's arms go with --import; the profile's own -s does not mix */
TEST(ah_tune_template)
{
    const char *v[] = {"--ext", "-s", "\\/", "--new", "--template=t", "--ext-arm", "\\/", "--ext-arm",
                       "[TCP:flags:PA]-drop-| \\/", "--ext-tune", "rr:fails=1", "--new", "--import", "t",
                       "--filter-tcp", "80", "--ext-tune", "rr:fails=2", NULL};
    const char *bad[] = {"--ext", "-s", "\\/", "--new", "--template=t", "--ext-arm", "\\/", "--new", "--import", "t",
                         "--filter-tcp", "80", "-s", "\\/", NULL};
    sbuf e;
    sb_init(&e);
    CHECK_INT(activate(v), 0);
    ext_profile_list(&e);
    CHECK(strstr(e.data, "2: ") && strstr(e.data, ": 2 arms"));
    ext_reset();
    CHECK(activate(bad) < 0);
    ext_reset();
    sb_free(&e);
}

TEST(ah_success)
{
    const char *f = tmp("ok.txt"), *dbg = tmp("ok.log");
    const char *v[] = {"--ext", "-s", "\\/", "--hostlist-auto", f, "--hostlist-auto-fail-threshold", "2",
                       "--hostlist-auto-debug", dbg, NULL};
    uint8_t b[200];
    static char big[4200];
    xoffline *x = NULL;
    strategy *cmd;
    sbuf e;
    char *d;
    remove(f);
    remove(dbg);
    memset(big, 'x', sizeof(big) - 1);
    CHECK_INT(activate(v), 0);
    sb_init(&e);
    cmd = strategy_parse("\\/", &e);
    sb_free(&e);
    x = xoff_new();
    if (!x || !cmd)
        goto out;
    /* a redirect to another domain: a failure */
    CHECK(open_req(x, cmd, 41001, 1000) == NULL);
    go(x, cmd, b,
       mk(b, 41001, 1, 0x18, 5001, 1031, "HTTP/1.1 302 Found\r\nLocation: http://warning.rt.ru/\r\n\r\n"), DIR_IN,
       1010);
    /* a redirect within the domain is not one; data past incoming-maxseq
     * is a success: the counter starts over */
    CHECK(open_req(x, cmd, 41002, 2000) == NULL);
    go(x, cmd, b, mk(b, 41002, 1, 0x18, 5001, 1031, "HTTP/1.1 302 Found\r\nLocation: /a\r\n\r\n"), DIR_IN, 2010);
    {
        size_t n = mk(b, 41002, 1, 0x10, 5001 + 4100, 1031, "");
        go(x, cmd, b, n, DIR_IN, 2011);
    }
    /* one more failure: 1/2, not added */
    CHECK(open_req(x, cmd, 41003, 3000) == NULL);
    go(x, cmd, b, mk(b, 41003, 1, 0x14, 5001, 1031, ""), DIR_IN, 3010);
    d = slurp(f);
    CHECK_STR(d, "");
    free(d);
    /* the client past retrans-maxseq: a success too */
    CHECK(open_req(x, cmd, 41004, 4000) == NULL);
    go(x, cmd, b, mk(b, 41004, 0, 0x18, 1001 + 40000, 5001, "x"), DIR_OUT, 4010);
    CHECK(open_req(x, cmd, 41005, 5000) == NULL);
    go(x, cmd, b, mk(b, 41005, 1, 0x14, 5001, 1031, ""), DIR_IN, 5010);
    d = slurp(f);
    CHECK_STR(d, "");
    free(d);
    xah_debug_log(NULL);
    d = slurp(dbg);
    CHECK(strstr(d, "proto http : rseq 1 : redirect to another domain") != NULL);
    CHECK(strstr(d, "proto http : rseq 1 : incoming RST") != NULL);
    CHECK(strstr(d, "fail counter 1/2") != NULL);
    CHECK(strstr(d, "fail counter reset. website is working.") != NULL);
    CHECK(strstr(d, "fail counter 2/2") == NULL);
    free(d);
    (void)big;
out:
    xoff_free(x);
    strategy_free(cmd);
    ext_reset();
    remove(f);
    remove(dbg);
    CHECK_INT((int)xlists_count(), 0);
}

/* UDP: the counts, on a flow whose host is known */
TEST(ah_udp)
{
    const char *f = tmp("udp.txt");
    xprofiles ps;
    xprofile *p;
    ct_flow fl;
    xah_pkt k;
    gpkt g;
    char *d;
    const char *v[] = {"--hostlist-auto", f, "--hostlist-auto-fail-threshold", "1", "-s", "\\/", NULL};
    remove(f);
    CHECK_STR(build(v, &ps), "OK");
    if (ps.n != 1)
        goto out;
    p = ps.v[0];
    memset(&fl, 0, sizeof(fl));
    memset(&g, 0, sizeof(g));
    memset(&k, 0, sizeof(k));
    g.l4 = LAYER_UDP;
    fl.proto = 17;
    fl.ver = 4;
    fl.chost = xstrdup("q.org");
    fl.ah_check = 1;
    k.p = &g;
    k.f = &fl;
    k.now_ms = 1000;
    /* two back: a success */
    fl.client.pcounter = 1;
    fl.server.pcounter = 2;
    xah_udp(p, &k);
    CHECK(fl.ah_final);
    /* four out, one back: a failure */
    fl.ah_final = 0;
    fl.server.pcounter = 1;
    fl.client.pcounter = 3;
    xah_udp(p, &k);
    CHECK(!fl.ah_final);
    fl.client.pcounter = 4;
    xah_udp(p, &k);
    CHECK(fl.ah_final);
    d = slurp(f);
    CHECK_STR(d, "q.org\n");
    free(d);
    free(fl.chost);
out:
    xprof_free(&ps);
    remove(f);
}

/* The IP cache in the choice: a DNS answer names the server; the next flow
 * to it knows its host from the SYN */
static size_t mk_udp(uint8_t *b, const uint8_t *src, const uint8_t *dst, unsigned sp, unsigned dp,
                     const uint8_t *data, size_t dl)
{
    size_t n = 28 + dl;
    memset(b, 0, 28);
    b[0] = 0x45;
    put16(b + 2, (unsigned)n);
    b[8] = 64;
    b[9] = 17;
    memcpy(b + 12, src, 4);
    memcpy(b + 16, dst, 4);
    put16(b + 10, inet_csum(b, 20, 0));
    put16(b + 20, sp);
    put16(b + 22, dp);
    put16(b + 24, (unsigned)(8 + dl));
    memcpy(b + 28, data, dl);
    return n;
}

static strategy *syn_to(xoffline *x, strategy *cmd, const uint8_t *srv, unsigned cport, uint64_t t)
{
    uint8_t b[64];
    mk(b, cport, 0, 0x02, 1000, 0, "");
    memcpy(b + 16, srv, 4);
    put16(b + 10, 0);
    put16(b + 10, inet_csum(b, 20, 0));
    return go(x, cmd, b, 40, DIR_OUT, t);
}

TEST(ah_ipcache_pick)
{
    static const uint8_t dns[4] = {8, 8, 8, 8}, cli[4] = {10, 0, 0, 2};
    const char *v1[] = {"--ext", "-s", "\\/", "--hostlist-domains", "example.org", "--new", "-s",
                        "[TCP:flags:S]-drop-| \\/", "--ext-ipcache-hostname", NULL};
    const char *v0[] = {"--ext", "-s", "\\/", "--hostlist-domains", "example.org", "--new", "-s",
                        "[TCP:flags:S]-drop-| \\/", NULL};
    const char *const *vs[2] = {v0, v1};
    uint8_t a[512], b[600];
    size_t an = dns_answer(a, "www.example.org", 1), n;
    for (int with = 0; with < 2; with++) {
        xoffline *x = NULL;
        strategy *cmd, *st;
        sbuf e;
        CHECK_INT(activate((const char **)vs[with]), 0);
        sb_init(&e);
        cmd = strategy_parse("\\/", &e);
        sb_free(&e);
        x = xoff_new();
        if (!x || !cmd) {
            strategy_free(cmd);
            xoff_free(x);
            ext_reset();
            continue;
        }
        n = mk_udp(b, dns, cli, 53, 5353, a, an);
        go(x, cmd, b, n, DIR_IN, 1000);
        CHECK_INT((int)xipc_count(), with ? 2 : 0);
        st = syn_to(x, cmd, A2, 42000, 2000);
        if (with)
            CHECK(st == cmd); /* profile 1: www.example.org from the cache */
        else
            CHECK(st && st != cmd);
        /* the TTL of the first reply goes into the cache for the next flow */
        xoff_free(x);
        strategy_free(cmd);
        ext_reset();
        CHECK_INT((int)xipc_count(), 0);
    }
    CHECK_INT((int)xlists_count(), 0);
}

TEST(ah_ttl)
{
    const char *v[] = {"--ext", "-s", "\\/", NULL};
    uint8_t b[200];
    xoffline *x;
    strategy *cmd;
    sbuf e;
    CHECK_INT(activate(v), 0);
    sb_init(&e);
    cmd = strategy_parse("\\/", &e);
    sb_free(&e);
    x = xoff_new();
    if (x && cmd) {
        go(x, cmd, b, mk(b, 43001, 0, 0x02, 1000, 0, ""), DIR_OUT, 1000);
        go(x, cmd, b, mk(b, 43001, 1, 0x12, 5000, 1001, ""), DIR_IN, 1001);
        CHECK_INT(xipc_get_ttl(4, A1, NULL), 50);
    }
    xoff_free(x);
    strategy_free(cmd);
    ext_reset();
}

void suite_autolist(void)
{
    RUN(ah_ipcache);
    RUN(ah_dns);
    RUN(ah_list);
    RUN(ah_options);
    RUN(ah_counters);
    RUN(ah_rst);
    RUN(ah_flows);
    RUN(ah_tune_offline);
    RUN(ah_tune_template);
    RUN(ah_success);
    RUN(ah_udp);
    RUN(ah_ipcache_pick);
    RUN(ah_ttl);
}

#else
void suite_autolist(void) {}
#endif
