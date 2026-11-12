/* geneva blockcheck (X12b, src/ext/blockcheck.c, z2xlate.c): the nfqws2
 * lines into geneva strategies, the grid's control flow and the report.
 * tests/e2e/blockcheck_grid.sh compares the whole grid with zapret2's own
 * scripts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/blockcheck.h"
#  include "ext/z2xlate.h"
#  include "strategy.h"

static int ext_on(void)
{
    static const optdef defs[] = {EXT_OPT, EXT_CTRACK_OPTS, {NULL, 0, 0, NULL, NULL}};
    const char *argv[] = {"--ext", NULL};
    args_t a;
    char err[128];
    int r;
    if (args_parse(&a, 1, (char **)argv, defs, err, sizeof(err)) < 0)
        return -2;
    r = ext_parse_args(&a, "test");
    args_free(&a);
    return r;
}

static const char *xl(const char *in)
{
    static char buf[1024];
    sbuf o, e;
    sb_init(&o);
    sb_init(&e);
    if (z2x_translate(in, &o, &e) == 0)
        snprintf(buf, sizeof(buf), "%s", o.data);
    else
        snprintf(buf, sizeof(buf), "ERR %s", e.data);
    sb_free(&o);
    sb_free(&e);
    return buf;
}

TEST(z2x_lines)
{
    CHECK_STR(xl("--payload=http_req --lua-desync=multisplit:pos=method+2"),
              "[FLOW:n:a]-xwhen{iff=L7:payload:http_req}(xsplit{pos=method+2},)-| \\/");
    /* a chain shares its filter; drop ends it */
    CHECK_STR(xl("--payload=quic_initial --lua-desync=send:ipfrag:ipfrag_pos_udp=8 --lua-desync=drop"),
              "[FLOW:n:a]-xwhen{iff=L7:payload:quic_initial}(xsend{ipfrag;ipfrag_pos_udp=8}(drop,),)-| \\/");
    /* other filters: the later instances are the "else" too */
    CHECK_STR(xl("--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=3:repeats=1 "
                 "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip_ttl=1"),
              "[FLOW:n:a]-xwhen{iff=L7:payload:tls_client_hello}(xfake{blob=fake_default_tls;ip_ttl=3;repeats=1}("
              "xwhen{iff=FLOW:n:s1<d1}(xwhen{iff=L7:payload:empty}(xmod{ip_ttl=1},),),),"
              "xwhen{iff=FLOW:n:s1<d1}(xwhen{iff=L7:payload:empty}(xmod{ip_ttl=1},),))-| \\/");
    /* no --payload: all; tls_mod, the wssize before */
    CHECK_STR(xl("--lua-desync=wssize:wsize=1:scale=6 --lua-desync=syndata:blob=fake_default_tls:tls_mod=rnd,dupsid"),
              "[FLOW:n:a]-xwssize{wsize=1;scale=6}(xsyndata{blob=fake_default_tls;tlsmod=rnd,dupsid},)-| \\/");
    CHECK_STR(xl("--payload=http_req --lua-desync=http_hostcase"),
              "[FLOW:n:a]-xwhen{iff=L7:payload:http_req}(xhttp{hostcase},)-| \\/");
    CHECK_STR(xl("--payload=http_req --lua-desync=http_hostcase:spell=hoSt"),
              "[FLOW:n:a]-xwhen{iff=L7:payload:http_req}(xhttp{hostcase=hoSt},)-| \\/");
    CHECK_STR(xl("--payload=all --lua-desync=http_unixeol"), "[FLOW:n:a]-xhttp{unixeol}-| \\/");
    CHECK_STR(xl("--lua-desync=multidisorder_legacy:pos=2:seqovl=1"),
              "[FLOW:n:a]-xdisorder{legacy;pos=2;seqovl=1}-| \\/");
    CHECK_STR(xl("--in-range=-s1 --lua-desync=oob:urp=midsld"), "[FLOW:n:a]-xoob{urp=midsld}-| \\/");
    /* zapret2 reads one marker of a list with atoi */
    CHECK_STR(xl("--lua-desync=fakedsplit:pos=method+2,midsld"), "[FLOW:n:a]-xfakedsplit{pos=method+2}-| \\/");
    CHECK_STR(xl("--lua-desync=fakeddisorder:pos=1,sniext+1,host+1"), "[FLOW:n:a]-xfakeddisorder{pos=1}-| \\/");
    CHECK_STR(xl("--lua-desync=fakeddisorder:pos=midsld"), "[FLOW:n:a]-xfakeddisorder{pos=midsld}-| \\/");
    CHECK_STR(xl("--lua-desync=fakeddisorder:pos=midsld-2,x"), "[FLOW:n:a]-xfakeddisorder{pos=midsld-2}-| \\/");
    CHECK_STR(xl("--lua-desync=fakedsplit:pos=midsld,host+1"), "ERR bad marker midsld,host+1");
    /* --out-range=x never runs; --lua-init is dropped */
    CHECK_STR(xl("--lua-init=x=1 --lua-desync=multisplit --out-range=x --lua-desync=drop"),
              "[FLOW:n:a]-xsplit-| \\/");
    CHECK_STR(xl("--lua-desync=luaexec:code=x"), "ERR no geneva action for --lua-desync=luaexec");
    CHECK_STR(xl("--blob=b:@f.bin --lua-desync=fake:blob=b"), "ERR no geneva equivalent of --blob=b:@f.bin");
    CHECK_STR(xl("--lua-desync=drop --lua-desync=multisplit"), "ERR drop must be the last instance");
    CHECK_STR(xl("--payload=http_req"), "ERR no --lua-desync");
    CHECK_STR(xl("--lua-desync=drop:x"), "ERR drop takes no arguments");
}

/* the oracle: the lines in ok[] work; every line is kept */
typedef struct {
    const char *const *ok;
    sbuf lines;
    int n, untranslated, bad_parse;
} oracle;

static int otest(void *ctx, const char *nfq, const char *gen)
{
    oracle *o = ctx;
    o->n++;
    sb_printf(&o->lines, "%s\n", nfq);
    if (!gen) {
        o->untranslated += !strstr(nfq, "luaexec");
    } else {
        sbuf e;
        strategy *st;
        sb_init(&e);
        st = strategy_parse(gen, &e);
        o->bad_parse += !st;
        strategy_free(st);
        sb_free(&e);
    }
    for (int i = 0; o->ok && o->ok[i]; i++)
        if (!strcmp(o->ok[i], nfq))
            return 1;
    return 0;
}

static void run(bc_run *b, oracle *o, int level, int ipv, const char *const *ok)
{
    bc_init(b);
    memset(o, 0, sizeof(*o));
    sb_init(&o->lines);
    o->ok = ok;
    b->level = level;
    b->test = otest;
    b->ctx = o;
    for (int t = 0; t < BC_NTESTS; t++)
        bc_scripts(b, t, "a.example", ipv);
}

static int has(const oracle *o, const char *line)
{
    const char *p = o->lines.data;
    size_t n = strlen(line);
    while (p && (p = strstr(p, line)) != NULL) {
        if ((p == o->lines.data || p[-1] == '\n') && p[n] == '\n')
            return 1;
        p += n;
    }
    return 0;
}

TEST(bc_grid)
{
    bc_run b;
    oracle o;
    CHECK_INT(ext_on(), 0);
    /* every line translates (but zapret2's Lua code) and parses */
    for (int level = BC_VERYQUICK; level <= BC_FORCE; level++)
        for (int ipv = 4; ipv <= 6; ipv += 2) {
            run(&b, &o, level, ipv, NULL);
            CHECK_INT(o.untranslated, 0);
            CHECK_INT(o.bad_parse, 0);
            CHECK(o.n > 1000);
            CHECK_INT(b.ntests, o.n);
            /* nothing worked: each test reports "not working" */
            CHECK_INT(b.nrep, BC_NTESTS);
            {
                char want[96];
                snprintf(want, sizeof(want), "curl_test_http ipv%d a.example : nfqws2 not working", ipv);
                CHECK_STR(b.rep[0].line, want);
            }
            bc_free(&b);
            sb_free(&o.lines);
        }
    /* the sizes of the all-fail grid (tests/e2e/blockcheck_grid.sh: zapret2's) */
    run(&b, &o, BC_STANDARD, 4, NULL);
    CHECK_INT(o.n, 30386);
    CHECK(has(&o, "--payload=http_req --lua-desync=http_hostcase:spell=hoSt"));
    CHECK(has(&o, "--payload=quic_initial --lua-desync=fake:blob=fake_default_quic:repeats=20"));
    CHECK(!has(&o, "--payload=quic_initial --lua-desync=send:ip6_hopbyhop --lua-desync=drop"));
    bc_free(&b);
    sb_free(&o.lines);
    run(&b, &o, BC_STANDARD, 6, NULL);
    CHECK(has(&o, "--payload=quic_initial --lua-desync=send:ip6_hopbyhop --lua-desync=drop"));
    CHECK(has(&o, "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip6_hopbyhop:repeats=1"));
    bc_free(&b);
    sb_free(&o.lines);
    ext_reset();
}

TEST(bc_shortcuts)
{
    static const char *const split[] = {"--payload=http_req --lua-desync=multisplit:pos=method+2", NULL};
    static const char *const tls1[] = {"--payload=tls_client_hello --lua-desync=multisplit:pos=2", NULL};
    bc_run b;
    oracle o;
    CHECK_INT(ext_on(), 0);
    /* multisplit works on http: no fakedsplit, no fake + multisplit */
    run(&b, &o, BC_STANDARD, 4, split);
    CHECK_INT(b.need_multisplit, 1); /* the last test (tls13) found none */
    CHECK(!has(&o, "--payload=http_req --lua-desync=fakedsplit:pos=method+2:ip_ttl=1:repeats=1"));
    CHECK(has(&o, "--payload=http_req --lua-desync=fakeddisorder:pos=method+2:ip_ttl=1:repeats=1"));
    CHECK(!has(&o, "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_ttl=1:repeats=1 "
                   "--lua-desync=multisplit:pos=method+2"));
    CHECK(has(&o, "--payload=http_req --lua-desync=fake:blob=fake_default_http:ip_ttl=1:repeats=1 "
                  "--lua-desync=multidisorder:pos=method+2"));
    CHECK_STR(b.rep[0].line, "curl_test_http ipv4 a.example : nfqws2 --payload=http_req "
                             "--lua-desync=multisplit:pos=method+2");
    CHECK_STR(b.rep[0].gen, "[FLOW:n:a]-xwhen{iff=L7:payload:http_req}(xsplit{pos=method+2},)-| \\/");
    CHECK_STR(b.rep[1].line, "curl_test_https_tls12 ipv4 a.example : nfqws2 not working");
    bc_free(&b);
    sb_free(&o.lines);
    /* force tests all */
    run(&b, &o, BC_FORCE, 4, split);
    CHECK(has(&o, "--payload=http_req --lua-desync=fakedsplit:pos=method+2:ip_ttl=1:repeats=1"));
    bc_free(&b);
    sb_free(&o.lines);
    /* tls12: no wssize pass once the first worked */
    run(&b, &o, BC_STANDARD, 4, tls1);
    CHECK(!has(&o, "--lua-desync=wssize:wsize=1:scale=6 --payload=tls_client_hello --lua-desync=multisplit:pos=2"));
    CHECK(has(&o, "--lua-desync=wssize:wsize=1:scale=6 --payload=tls_client_hello "
                  "--lua-desync=fake:blob=fake_default_tls:ip_ttl=1:repeats=1"));
    bc_free(&b);
    sb_free(&o.lines);
    run(&b, &o, BC_STANDARD, 4, NULL);
    CHECK(has(&o, "--lua-desync=wssize:wsize=1:scale=6 --payload=tls_client_hello --lua-desync=multisplit:pos=2"));
    bc_free(&b);
    sb_free(&o.lines);
    ext_reset();
}

TEST(bc_levels)
{
    /* the fake of 25-fake.sh with TTL 3 works */
    static const char *const fake3[] = {
        "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=3:repeats=1", NULL};
    bc_run b;
    oracle o;
    int n_vq, n_std;
    CHECK_INT(ext_on(), 0);
    run(&b, &o, BC_VERYQUICK, 4, fake3);
    n_vq = o.n;
    /* veryquick: the rest of the vary for TTL 3 is skipped */
    CHECK(!has(&o, "--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:ip_ttl=3:repeats=1"));
    bc_free(&b);
    sb_free(&o.lines);
    run(&b, &o, BC_STANDARD, 4, fake3);
    n_std = o.n;
    CHECK(has(&o, "--payload=tls_client_hello --lua-desync=fake:blob=0x00000000:ip_ttl=3:repeats=1"));
    /* TTL 4 is not tried: the TTL loop stops */
    CHECK(!has(&o, "--payload=tls_client_hello --lua-desync=fake:blob=fake_default_tls:ip_ttl=4:repeats=1"));
    CHECK(n_vq < n_std);
    bc_free(&b);
    sb_free(&o.lines);
    /* TTL tests off */
    bc_init(&b);
    memset(&o, 0, sizeof(o));
    sb_init(&o.lines);
    b.test = otest;
    b.ctx = &o;
    b.max_ttl = 0;
    b.max_autottl = 0;
    bc_scripts(&b, BC_HTTP, "a.example", 4);
    CHECK(!strstr(o.lines.data, "ttl"));
    bc_free(&b);
    sb_free(&o.lines);
    ext_reset();
}

static int stop_after(void *ctx, const char *nfq, const char *gen)
{
    int *n = ctx;
    (void)nfq;
    (void)gen;
    return ++*n >= 3 ? -1 : 0;
}

TEST(bc_reports)
{
    bc_run b;
    sbuf j;
    FILE *f;
    char buf[4096];
    size_t got;
    int n = 0;
    bc_init(&b);
    b.testf = "curl_test_http";
    b.ipv = 4;
    bc_report(&b, "a.example", "nfqws2 --x", "[S]");
    bc_report(&b, "b.example", "nfqws2 --x", "[S]");
    bc_report(&b, "a.example", "nfqws2 --y", "[T]");
    bc_report(&b, "b.example", "nfqws2 not working", NULL);
    f = tmpfile();
    CHECK(f != NULL);
    if (f) {
        bc_print(&b, 2, f);
        rewind(f);
        got = fread(buf, 1, sizeof(buf) - 1, f);
        buf[got] = 0;
        fclose(f);
        CHECK_STR(buf, "\n* SUMMARY\n"
                       "curl_test_http ipv4 a.example : nfqws2 --x\n  geneva: [S]\n"
                       "curl_test_http ipv4 b.example : nfqws2 --x\n  geneva: [S]\n"
                       "curl_test_http ipv4 a.example : nfqws2 --y\n  geneva: [T]\n"
                       "curl_test_http ipv4 b.example : nfqws2 not working\n"
                       "\n* COMMON\n"
                       "curl_test_http ipv4 : nfqws2 --x\n  geneva: [S]\n"
                       "\n* COVERAGE\n"
                       "2/2 : curl_test_http ipv4 : nfqws2 --x\n  geneva: [S]\n"
                       "1/2 : curl_test_http ipv4 : nfqws2 not working\n"
                       "1/2 : curl_test_http ipv4 : nfqws2 --y\n  geneva: [T]\n"
                       "\nblockcheck optimizes test sequence. To save time some strategies can be skipped if their "
                       "test is considered useless.\nThat's why COMMON intersection can miss strategies that would "
                       "work for all domains, and COVERAGE counts can undercount.\nUse \"force\" scan level to test "
                       "all strategies and generate trustable results.\n");
    }
    sb_init(&j);
    bc_print_json(&b, 2, &j);
    CHECK(strstr(j.data, "\"common\":[{\"test\":\"curl_test_http ipv4\",\"nfqws2\":\"--x\",\"strategy\":\"[S]\"}]"));
    CHECK(strstr(j.data, "{\"domain\":\"b.example\",\"test\":\"curl_test_http ipv4\",\"result\":\"nfqws2 not working\"}"));
    CHECK(strstr(j.data, "{\"count\":2,\"test\":\"curl_test_http ipv4\",\"nfqws2\":\"--x\""));
    sb_free(&j);
    bc_free(&b);
    /* stopping ends the grid */
    CHECK_INT(ext_on(), 0);
    bc_init(&b);
    b.test = stop_after;
    b.ctx = &n;
    CHECK_INT(bc_scripts(&b, BC_HTTP, "a.example", 4), -1);
    CHECK_INT(n, 3);
    CHECK_INT(b.nrep, 0);
    bc_free(&b);
    ext_reset();
}

void suite_blockcheck(void);
void suite_blockcheck(void)
{
    RUN(z2x_lines);
    RUN(bc_grid);
    RUN(bc_shortcuts);
    RUN(bc_levels);
    RUN(bc_reports);
}

#else
void suite_blockcheck(void);
void suite_blockcheck(void) {}
#endif
