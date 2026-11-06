/* Stage X6a: profiles (src/ext/profile.c): zapret2's filters with their
 * parsing and matching, --new/--skip/--template/--import, the profile file,
 * the capture they need, and the choice of the strategy per packet with
 * the rediscovery once a flow's L7 protocol is known. */
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
#  include "ext/ext.h"
#  include "ext/l7.h"
#  include "ext/profile.h"
#  include "ext/xact.h"
#  include "ext/xtrig.h"

static const optdef defs[] = {
    {"strategy", 's', 1, "S", ""},
    {"strategy-file", 'f', 1, "F", ""},
    {"server-port", 'p', 1, "P", ""},
    EXT_OPT,
    EXT_PROFILE_OPTS,
    {NULL, 0, 0, NULL, NULL},
};

/* xprof_build on an argv; the message (or "OK") in a static buffer */
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

static int pf1(const char *s, xpf *out)
{
    xpf *v = NULL;
    size_t n = 0;
    int r = xprof_pf_list(s, &v, &n);
    if (!r && n)
        *out = v[n - 1];
    free(v);
    return r < 0 ? -1 : (int)n;
}

TEST(pr_filters)
{
    xpf f;
    xicf *ic = NULL;
    xipp *ip = NULL;
    size_t n = 0;
    uint32_t m, k;
    CHECK_INT(pf1("443", &f), 1);
    CHECK(f.from == 443 && f.to == 443 && !f.neg);
    CHECK_INT(pf1("80,443,1000-2000", &f), 3);
    CHECK(f.from == 1000 && f.to == 2000);
    CHECK_INT(pf1("*", &f), 1);
    CHECK(f.from == 1 && f.to == 65535 && !f.neg);
    CHECK_INT(pf1("~443", &f), 1);
    CHECK(f.neg && f.from == 443);
    CHECK_INT(pf1("0", &f), 1);
    CHECK(f.neg && !f.from && !f.to); /* deny */
    CHECK_INT(pf1("65536", &f), -1);
    CHECK_INT(pf1("2-1", &f), -1);
    CHECK_INT(pf1("1-", &f), -1);
    CHECK_INT(pf1("", &f), -1);
    CHECK_INT(pf1("80,", &f), -1);
    CHECK_INT(pf1("x", &f), -1);
    CHECK_INT(pf1("+80", &f), -1);
    CHECK_INT(xprof_icf_list("*,3,3:4,-", &ic, &n), 0);
    CHECK_INT((int)n, 4);
    CHECK(ic[0].mode == XF_ANY && ic[1].mode == XF_FILTER && ic[1].type == 3 && !ic[1].code_valid);
    CHECK(ic[2].code_valid && ic[2].code == 4 && ic[3].mode == XF_SKIP);
    free(ic), ic = NULL, n = 0;
    CHECK_INT(xprof_icf_list("3:", &ic, &n), -1);
    free(ic), ic = NULL, n = 0;
    CHECK_INT(xprof_icf_list("256", &ic, &n), -1);
    free(ic), ic = NULL, n = 0;
    CHECK_INT(xprof_ipp_list("47,*", &ip, &n), 0);
    CHECK(n == 2 && ip[0].proto == 47 && ip[0].mode == XF_FILTER && ip[1].mode == XF_ANY);
    free(ip), ip = NULL, n = 0;
    CHECK_INT(xprof_ipp_list("gre", &ip, &n), -1);
    free(ip);
    CHECK_INT(xprof_mark("0x10/0xf0", &m, &k), 0);
    CHECK(m == 0x10 && k == 0xf0);
    CHECK_INT(xprof_mark("16", &m, &k), 0);
    CHECK(m == 16 && k == 0xffffffffU);
    CHECK_INT(xprof_mark("010", &m, &k), 0);
    CHECK(m == 10); /* decimal, as sscanf("%u") */
    CHECK_INT(xprof_mark("0x1g", &m, &k), -1);
    CHECK_INT(xprof_mark("1/", &m, &k), -1);
    CHECK_INT(xprof_mark("4294967296", &m, &k), -1);
}

static xmatch mt(int ver, int proto, unsigned port, int l7, uint32_t mark)
{
    xmatch m;
    memset(&m, 0, sizeof(m));
    m.ver = ver, m.proto = proto, m.port = (uint16_t)port, m.l7 = l7, m.mark = mark;
    return m;
}

TEST(pr_match)
{
    xprofiles ps;
    xmatch m;
    {
        /* dp_match: L3, L7, ports, the defaults for unnamed protocols */
        const char *v[] = {"-s", "\\/", "--filter-tcp", "443", "--filter-l7", "tls", "--filter-l3", "ipv4",
                           "--new=web", "--filter-tcp", "80,443", "-s", "\\/",
                           "--new=any", "-s", "\\/", NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 3);
        CHECK(ps.v[0]->cmd && !ps.v[0]->st && ps.v[1]->st && !ps.v[1]->cmd);
        CHECK_STR(ps.v[1]->name, "web");
        m = mt(4, 6, 443, L7_TLS, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        m.ver = 6;
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        m = mt(4, 6, 443, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        CHECK_INT(xprof_find(&ps, &m, 1), 0); /* any_l7 */
        m = mt(4, 17, 443, L7_QUIC, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 2); /* web takes no UDP: a tcp filter denies the rest */
        m = mt(4, 1, 0, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        m = mt(4, 47, 0, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        xprof_free(&ps);
    }
    {
        /* negation, "*", "0", ICMP, IP protocols, the mark */
        const char *v[] = {"--filter-tcp", "~80", "--filter-mark", "0x10/0x10", "--new",
                           "--filter-udp", "*", "--filter-icmp", "3:4", "--new",
                           "--filter-ipp", "47", "--filter-tcp", "0", NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 3);
        CHECK(!ps.v[0]->cmd && !ps.v[0]->st); /* filters but no strategy: a profile that does nothing */
        m = mt(4, 6, 443, L7_UNKNOWN, 0x30);
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        m.mark = 0x20;
        CHECK_INT(xprof_find(&ps, &m, 0), -1);
        m = mt(6, 6, 80, L7_UNKNOWN, 0x10);
        CHECK_INT(xprof_find(&ps, &m, 0), -1);
        m = mt(4, 17, 9999, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        m = mt(4, 17, 0, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), -1); /* port 0 never matches */
        m = mt(6, 58, 0, L7_UNKNOWN, 0);
        m.icmp_type = 3, m.icmp_code = 4;
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        m.icmp_code = 1;
        CHECK_INT(xprof_find(&ps, &m, 0), -1);
        m = mt(4, 47, 0, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        m = mt(4, 6, 80, L7_UNKNOWN, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), -1);
        xprof_free(&ps);
    }
    {
        /* "known" and "unknown" of --filter-l7; "all" is every protocol */
        const char *v[] = {"--filter-l7", "known", "-s", "\\/", "--new", "--filter-l7", "unknown",
                           "--new", "--filter-l7", "tls", "--filter-l7", "all", NULL};
        CHECK_STR(build(v, &ps), "OK");
        m = mt(4, 6, 1, L7_HTTP, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        m.l7 = L7_UNKNOWN;
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        CHECK(ps.v[2]->b_l7 && !ps.v[2]->l7);
        xprof_free(&ps);
    }
}

TEST(pr_build)
{
    xprofiles ps;
    {
        /* no profile option: no profiles */
        const char *v[] = {"-s", "\\/", "-p", "443", NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 0);
    }
    {
        /* the command's options only before the first --new: no profile 0;
         * --skip, --template and --import */
        const char *v[] = {"-p", "443", "--new", "--template=base", "--filter-tcp", "80", "--filter-l3", "ipv4", "--filter-mark", "1",
                           "-s", "[TCP:flags:S]-drop-| \\/", "--filter-l7", "http",
                           "--new", "--skip", "--filter-tcp", "1",
                           "--new=a", "--filter-tcp", "443", "--filter-l3", "ipv6", "--import", "base",
                           "--new=b", "-s", "\\/", "--import", "base", NULL};
        xmatch m;
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 2);
        CHECK_STR(ps.v[0]->name, "a");
        CHECK(ps.v[0]->n == 1 && ps.v[1]->n == 2);
        CHECK(ps.v[0]->ipv4 && ps.v[0]->ipv6); /* L3 is added */
        CHECK_INT((int)ps.v[0]->ntcp, 2);      /* the lists appended */
        CHECK(ps.v[0]->b_l7 && ps.v[0]->l7 == 1ULL << L7_HTTP);
        CHECK(ps.v[0]->st && ps.v[0]->st->nout == 1); /* the template's strategy */
        CHECK(ps.v[1]->st && ps.v[1]->st->nout == 0); /* its own wins */
        CHECK(!ps.v[0]->mark_mask); /* the mark is not imported (dp_copy) */
        m = mt(6, 6, 80, L7_HTTP, 0);
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--new", "--template", "--filter-tcp", "1", "--new", "--import", "x", NULL};
        CHECK_STR(build(v, &ps), "profile 3: template \"x\" not found (a --template comes before its --import)");
    }
    {
        const char *v[] = {"--template=t", "--new", "--template=t", "--new", "-s", "\\/", NULL};
        CHECK_STR(build(v, &ps), "template \"t\" already present");
    }
    {
        const char *v[] = {"--new", "-s", "\\/", "-s", "\\/", NULL};
        CHECK_STR(build(v, &ps), "profile 2: two strategies in one profile (-s or -f once per profile)");
    }
    {
        const char *v[] = {"--new", "-s", "[TCP:flags:S]-nope-| \\/", NULL};
        CHECK(!strncmp(build(v, &ps), "profile 1: ", 11));
    }
    {
        const char *v[] = {"--new", "--filter-l7", "~tls", NULL};
        CHECK_STR(build(v, &ps), "profile 2: bad --filter-l7: \"~\" is not for --filter-l7");
    }
    {
        const char *v[] = {"--new", "--filter-l3", "ipv5", NULL};
        CHECK_STR(build(v, &ps), "profile 2: bad --filter-l3 ipv5 (ipv4, ipv6 or ipv4,ipv6)");
    }
    {
        const char *v[] = {"-s", "\\/", "--template=x", NULL};
        CHECK_STR(build(v, &ps), "profile 1 has the command's strategy and cannot be a template");
    }
    {
        const char *v[] = {"--skip", "--filter-tcp", "1", NULL};
        CHECK_STR(build(v, &ps), "no profile left (every one is skipped or a template)");
    }
    {
        const char *v[] = {"--new", "-f", "/nonexistent/geneva-strategy", NULL};
        CHECK_STR(build(v, &ps), "profile 2: cannot read /nonexistent/geneva-strategy");
    }
}

static const char *write_tmp(const char *text)
{
    static char path[64];
    FILE *f;
    snprintf(path, sizeof(path), "/tmp/geneva-test-prof-%d.ini", (int)plat_getpid());
    f = fopen(path, "wb");
    if (!f)
        return NULL;
    fputs(text, f);
    fclose(f);
    return path;
}

TEST(pr_file)
{
    xprofiles ps;
    const char *path = write_tmp("# profiles\n"
                                 "[template base]\n"
                                 "filter-tcp = 80\n"
                                 "\n"
                                 "[profile tls]\n"
                                 "  filter-tcp = 443   # a comment\n"
                                 "import = base\n"
                                 "filter-l7 = tls\n"
                                 "strategy = [TCP:flags:PA]-drop-| \\/\n"
                                 "[profile]\n"
                                 "skip = 1\n"
                                 "[profile last]\n"
                                 "skip = no\n"
                                 "filter-udp=443\n");
    CHECK(path != NULL);
    if (!path)
        return;
    {
        const char *v[] = {"-s", "\\/", "--filter-tcp", "22", "--ext-profile", path, NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 3);
        CHECK(ps.v[0]->cmd);
        CHECK_STR(ps.v[1]->name, "tls");
        CHECK_INT((int)ps.v[1]->ntcp, 2);
        CHECK(ps.v[1]->st && ps.v[1]->st->nout == 1);
        CHECK_STR(ps.v[2]->name, "last");
        CHECK(!ps.v[2]->st);
        xprof_free(&ps);
    }
    remove(path);
    path = write_tmp("[profile a]\nfilter-tcp = x\n");
    {
        const char *v[] = {"--ext-profile", path, NULL};
        char want[200];
        snprintf(want, sizeof(want), "%s:2: bad --filter-tcp x ([~]PORT[-PORT],... or *)", path);
        CHECK_STR(build(v, &ps), want);
    }
    path = write_tmp("filter-tcp = 1\n");
    {
        const char *v[] = {"--ext-profile", path, NULL};
        char want[200];
        snprintf(want, sizeof(want), "%s:1: \"filter-tcp = 1\" outside of a [profile] section", path);
        CHECK_STR(build(v, &ps), want);
    }
    path = write_tmp("[profile a]\nhostname = x\n");
    {
        const char *v[] = {"--ext-profile", path, NULL};
        char want[200];
        snprintf(want, sizeof(want), "%s:2: unknown key \"hostname\"", path);
        CHECK_STR(build(v, &ps), want);
    }
    path = write_tmp("[group a]\n");
    {
        const char *v[] = {"--ext-profile", path, NULL};
        char want[200];
        snprintf(want, sizeof(want), "%s:1: unknown section [group] (profile or template)", path);
        CHECK_STR(build(v, &ps), want);
    }
    path = write_tmp("[template]\n");
    {
        const char *v[] = {"--ext-profile", path, NULL};
        char want[200];
        snprintf(want, sizeof(want), "%s:1: a template needs a name", path);
        CHECK_STR(build(v, &ps), want);
    }
    path = write_tmp("[profile a]\nname = b\n");
    {
        const char *v[] = {"--ext-profile", path, NULL};
        char want[200];
        snprintf(want, sizeof(want), "%s:2: \"name\" is not for the file (sections start profiles)", path);
        CHECK_STR(build(v, &ps), want);
    }
    remove(path);
}

static const char *cap(const char **argv, int ports)
{
    static char buf[300];
    xprofiles ps;
    xcapture c;
    sbuf e, o;
    const char *r = build(argv, &ps);
    if (strcmp(r, "OK"))
        return r;
    sb_init(&e);
    sb_init(&o);
    if (xprof_capture(&ps, ports, &c, &e) < 0) {
        snprintf(buf, sizeof(buf), "%s", e.data);
    } else {
        ports_format(&c.ports, &o, ",", "-");
        snprintf(buf, sizeof(buf), "%s tcp=%d udp=%d ok=%d icmp=%d ipp=%d", o.data ? o.data : "", c.tcp, c.udp, c.ports_ok, c.icmp,
                 c.nipp ? c.ipp[0] : -1);
    }
    sb_free(&e);
    sb_free(&o);
    xprof_free(&ps);
    return buf;
}

TEST(pr_capture)
{
    {
        const char *v[] = {"--filter-tcp", "80,443", "--new", "--filter-udp", "443", "--new", "--filter-tcp", "443",
                           "--new", "--filter-icmp", "3", "--filter-ipp", "47", NULL};
        CHECK_STR(cap(v, 1), "80,443 tcp=1 udp=1 ok=1 icmp=1 ipp=47");
    }
    {
        const char *v[] = {"--filter-tcp", "80", "--new=all", "-s", "\\/", NULL};
        CHECK_STR(cap(v, 1), "profile 2 (all) takes every port: give -p (and --proto)");
        CHECK_STR(cap(v, 0), "80 tcp=1 udp=0 ok=0 icmp=0 ipp=-1");
    }
    {
        const char *v[] = {"--filter-tcp", "~80", NULL};
        CHECK_STR(cap(v, 1), "profile 1 takes every port: give -p (and --proto)");
    }
    {
        const char *v[] = {"--filter-icmp", "*", NULL};
        CHECK_STR(cap(v, 1), " tcp=0 udp=0 ok=1 icmp=1 ipp=-1");
    }
    {
        const char *v[] = {"--filter-ipp", "*", NULL};
        CHECK_STR(cap(v, 0), "--filter-ipp=* cannot be captured: name the protocols (or --firewall none and own rules)");
    }
    {
        const char *v[] = {"--filter-tcp", "0", NULL};
        CHECK_STR(cap(v, 1), "the profiles name no port or protocol to capture: give -p");
    }
}

/* ---- the strategy per packet (apply's path: xoff_packet) ------------------- */

static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8), p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { put16(p, v >> 16), put16(p + 2, v & 0xffff); }

/* 10.0.0.1:40000 <-> 10.0.0.2:dport, TCP; from_server swaps the ends */
static size_t mk(uint8_t *b, unsigned dport, int from_server, unsigned flags, uint32_t seq, const char *d)
{
    size_t dl = strlen(d), l4 = 20 + dl;
    uint8_t *t = b + 20;
    memset(b, 0, 40);
    b[0] = 0x45;
    put16(b + 2, (unsigned)(20 + l4));
    b[8] = 64;
    b[9] = 6;
    b[12] = 10, b[15] = from_server ? 2 : 1;
    b[16] = 10, b[19] = from_server ? 1 : 2;
    put16(t, from_server ? dport : 40000);
    put16(t + 2, from_server ? 40000 : dport);
    put32(t + 4, seq);
    t[12] = 5 << 4;
    t[13] = (uint8_t)flags;
    put16(t + 14, 64000);
    memcpy(t + 20, d, dl);
    return 20 + l4;
}

/* an ICMP port unreachable from 10.0.0.2 that carries packet q */
static size_t mk_icmp(uint8_t *b, const uint8_t *q, size_t qn)
{
    size_t n = 20 + 8 + (qn > 48 ? 48 : qn);
    memset(b, 0, 28);
    b[0] = 0x45;
    put16(b + 2, (unsigned)n);
    b[8] = 64;
    b[9] = 1;
    b[12] = 10, b[15] = 2;
    b[16] = 10, b[19] = 1;
    b[20] = 3, b[21] = 3;
    memcpy(b + 28, q, n - 28);
    return n;
}

typedef struct {
    int n;
} rp_ud;

static void rp(void *ud, const uint8_t *raw, size_t len, strat_dir dir, unsigned piece, unsigned pieces, void *xctx)
{
    (void)ud, (void)raw, (void)len, (void)dir, (void)piece, (void)pieces, (void)xctx;
}

/* the strategy xoff_packet picks for a packet, and its verdict */
static strategy *pick(xoffline *x, strategy *cmd, const uint8_t *b, size_t n, strat_dir dir, uint64_t t, int *v)
{
    gpkt *p = pkt_parse(b, n);
    strategy *st = cmd;
    rp_ud u = {0};
    CHECK(p != NULL);
    if (!p)
        return NULL;
    xoff_packet(x, &st, p, dir, t, b, n, rp, &u, v);
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

TEST(pr_pick)
{
    /* profile 1: TCP 80 with L7 http (the command's strategy), profile 2:
     * TCP 80 (its own), nothing for 443 */
    const char *v[] = {"--ext", "-s", "\\/", "--filter-tcp", "80", "--filter-l7", "http",
                       "--new=tcp80", "--filter-tcp", "80", "-s", "[TCP:flags:S]-drop-| \\/", NULL};
    uint8_t b[200], ic[200];
    size_t n, m;
    xoffline *x;
    strategy *cmd, *st;
    sbuf e;
    int verdict;
    CHECK_INT(activate(v), 0);
    CHECK_INT((int)ext_profiles(), 2);
    sb_init(&e);
    cmd = strategy_parse("\\/", &e);
    sb_free(&e);
    x = xoff_new();
    CHECK(x != NULL);
    if (!x || !cmd)
        goto out;
    /* the SYN: L7 not known, profile 2 */
    n = mk(b, 80, 0, 2, 1000, "");
    st = pick(x, cmd, b, n, DIR_OUT, 1, &verdict);
    CHECK(st && st != cmd && st->nout == 1);
    CHECK_INT(verdict, XOFF_RUN);
    /* an ICMP error about the flow goes with its profile */
    m = mk_icmp(ic, b, n);
    st = pick(x, cmd, ic, m, DIR_IN, 2, &verdict);
    CHECK(st && st != cmd && st->nout == 1);
    /* the request: HTTP known, profile 1 takes the flow */
    n = mk(b, 80, 0, 24, 1001, "GET / HTTP/1.1\r\nHost: a.b\r\n\r\n");
    st = pick(x, cmd, b, n, DIR_OUT, 3, &verdict);
    CHECK(st == cmd);
    /* and keeps it */
    n = mk(b, 80, 1, 24, 5000, "HTTP/1.1 200 OK\r\n\r\n");
    st = pick(x, cmd, b, n, DIR_IN, 4, &verdict);
    CHECK(st == cmd);
    n = mk(b, 80, 0, 16, 1030, "");
    st = pick(x, cmd, b, n, DIR_OUT, 5, &verdict);
    CHECK(st == cmd);
    /* port 443: no profile, the packet passes */
    n = mk(b, 443, 0, 2, 1000, "");
    st = pick(x, cmd, b, n, DIR_OUT, 6, &verdict);
    CHECK(st == NULL);
    CHECK_INT(verdict, XOFF_BYPASS);
    /* without a flow (no SYN seen): looked for per packet */
    n = mk(b, 8080, 0, 16, 1, "");
    st = pick(x, cmd, b, n, DIR_OUT, 7, &verdict);
    CHECK(st == NULL);
out:
    xoff_free(x);
    strategy_free(cmd);
    ext_reset();
}

void suite_profile(void)
{
    strategy_set_xact(&xact_ops);
    strategy_set_xtrig(&xtrig_ops);
    RUN(pr_filters);
    RUN(pr_match);
    RUN(pr_build);
    RUN(pr_file);
    RUN(pr_capture);
    strategy_set_xtrig(NULL);
    strategy_set_xact(NULL);
    RUN(pr_pick);
}

#else
void suite_profile(void) {}
#endif
