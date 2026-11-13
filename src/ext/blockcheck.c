/*
 * blockcheck2's grid (blockcheck.h): the scripts blockcheck2.d/standard of
 * zapret2 v1.0.6 ported line by line. Each script function is a C function
 * with the shell's loops, breaks and "ok" variables; T() is
 * pktws_curl_test_update.
 */
#include "ext/blockcheck.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "ext/z2xlate.h"
#include "json.h"
#include "strategy.h"

#define FORCE (b->level == BC_FORCE)
#define VQ (b->level == BC_VERYQUICK)
#define FR (b->fake_repeats)
#define V (b->ipv == 6 ? "6" : "")
#define NF(a) (sizeof(a) / sizeof((a)[0]))

static const char *const test_names[BC_NTESTS] = {"curl_test_http", "curl_test_https_tls12",
                                                  "curl_test_https_tls13", "curl_test_http3"};

const char *bc_test_name(int test)
{
    return test >= 0 && test < BC_NTESTS ? test_names[test] : "?";
}

void bc_init(bc_run *b)
{
    memset(b, 0, sizeof(*b));
    b->level = BC_STANDARD;
    b->min_ttl = 1;
    b->max_ttl = 12;
    b->min_autottl = 1;
    b->max_autottl = 5;
    b->fake_repeats = 1;
    b->need_multisplit = b->need_multidisorder = b->need_fake = -1;
    b->need_fakedsplit = b->need_fakeddisorder = b->need_hostfakesplit = -1;
}

void bc_free(bc_run *b)
{
    for (size_t i = 0; i < b->nrep; i++) {
        free(b->rep[i].key);
        free(b->rep[i].line);
        free(b->rep[i].domain);
        free(b->rep[i].test);
        free(b->rep[i].value);
        free(b->rep[i].gen);
    }
    free(b->rep);
    free(b->strategy);
    b->rep = NULL;
    b->nrep = 0;
    b->strategy = NULL;
}

void bc_report(bc_run *b, const char *domain, const char *value, const char *gen)
{
    bc_entry *e;
    sbuf s;
    b->rep = xrealloc(b->rep, (b->nrep + 1) * sizeof(*b->rep));
    e = &b->rep[b->nrep++];
    sb_init(&s);
    sb_printf(&s, "%s ipv%d", b->testf, b->ipv);
    e->test = sb_take(&s);
    sb_printf(&s, "%s : %s", e->test, value);
    e->key = sb_take(&s);
    sb_printf(&s, "%s %s : %s", e->test, domain, value);
    e->line = sb_take(&s);
    e->domain = xstrdup(domain);
    e->value = xstrdup(value);
    e->gen = gen ? xstrdup(gen) : NULL;
}

/* ---- pktws_curl_test_update ---------------------------------------------- */

static int T(bc_run *b, const char *fmt, ...) PRINTF_LIKE(2, 3);
static int T(bc_run *b, const char *fmt, ...)
{
    va_list ap;
    sbuf raw, nfq, gen, err;
    const char *p;
    int rc;
    if (b->stopped)
        return 0;
    sb_init(&raw);
    sb_init(&nfq);
    sb_init(&gen);
    sb_init(&err);
    va_start(ap, fmt);
    sb_vprintf(&raw, fmt, ap);
    va_end(ap);
    /* the shell's word splitting: one space between the words */
    for (p = raw.data; *p;) {
        size_t n;
        p += strspn(p, " ");
        n = strcspn(p, " ");
        if (!n)
            break;
        if (nfq.len)
            sb_putc(&nfq, ' ');
        sb_append(&nfq, p, n);
        p += n;
    }
    if (z2x_translate(nfq.data, &gen, &err) == 0) {
        strategy *st = strategy_parse(gen.data, &err);
        if (st)
            strategy_free(st);
        else
            sb_reset(&gen);
    }
    b->ntests++;
    if (b->log) {
        fprintf(b->log, "- %s ipv%d %s : nfqws2 %s\n", b->testf, b->ipv, b->domain, nfq.data);
        if (gen.len)
            fprintf(b->log, "  geneva: %s\n", gen.data);
        else
            fprintf(b->log, "  geneva: none (%s)\n", err.data ? err.data : "");
    }
    rc = b->test(b->ctx, nfq.data, gen.len ? gen.data : NULL);
    if (rc < 0) {
        b->stopped = 1;
        rc = 0;
    }
    if (!gen.len)
        rc = 0;
    if (b->log && !b->stopped)
        fprintf(b->log, "%s\n", rc ? "!!!!! AVAILABLE !!!!!" : "UNAVAILABLE");
    if (rc) {
        sbuf v;
        if (!b->strategy)
            b->strategy = xstrdup(nfq.data);
        sb_init(&v);
        sb_printf(&v, "nfqws2 %s", nfq.data);
        bc_report(b, b->domain, v.data, gen.data);
        sb_free(&v);
    }
    sb_free(&raw);
    sb_free(&nfq);
    sb_free(&gen);
    sb_free(&err);
    return rc;
}

/* ---- def.inc ------------------------------------------------------------- */

static const char *const fool46[] = {"tcp_md5", "badsum", "tcp_seq=-3000", "tcp_seq=1000000",
                                     "tcp_ack=-66000:tcp_ts_up", "tcp_ts=-1000", "tcp_flags_unset=ACK",
                                     "tcp_flags_set=SYN"};
static const char *const fool6[] = {"ip6_hopbyhop", "ip6_hopbyhop:ip6_hopbyhop2", "ip6_destopt", "ip6_routing",
                                    "ip6_ah"};

/* FOOLINGS_TCP, IPv6 extensions after the rest */
static size_t nfool(const bc_run *b)
{
    return NF(fool46) + (b->ipv == 6 ? NF(fool6) : 0);
}
static const char *fool(size_t i)
{
    return i < NF(fool46) ? fool46[i] : fool6[i - NF(fool46)];
}
static int md5(const char *fooling)
{
    return strstr(fooling, "tcp_md5") != NULL;
}

/* the TTL lists: seq MIN MAX unless MAX is 0 */
#define TTLS(t) for (int t = b->min_ttl; b->max_ttl && t <= b->max_ttl; t++)
#define ATTLS(t) for (int t = b->min_autottl; b->max_autottl && t <= b->max_autottl; t++)

/* "orig-ttl=1 with start/cutoff limiter drops empty ACK packet in response
 * to SYN,ACK": the '' and this of the scripts' "for f" loops */
static void ttl1(const bc_run *b, char *buf, size_t cap)
{
    snprintf(buf, cap, "--payload=empty --out-range=s1<d1 --lua-desync=pktmod:ip%s_ttl=1", V);
}
#define FS(f)                                                                                                \
    char f##_ttl1[96];                                                                                       \
    ttl1(b, f##_ttl1, sizeof(f##_ttl1));                                                                     \
    const char *const f##s[2] = {"", f##_ttl1};

#define MD5SEND "--payload=empty --out-range=<s1 --lua-desync=send:tcp_md5"
#define WSSIZE "--lua-desync=wssize:wsize=1:scale=6"
#define P_HTTP "--payload=http_req"
#define P_TLS "--payload=tls_client_hello"

static const char *mdis(const bc_run *b)
{
    return b->multidisorder_legacy ? "multidisorder_legacy" : "multidisorder";
}

static const char *const splits_http[] = {"method+2", "midsld", "method+2,midsld"};

/* ---- 10-http-basic.sh ---------------------------------------------------- */

static int s10_http(bc_run *b)
{
    static const char *const s[] = {"http_hostcase", "http_hostcase:spell=hoSt", "http_domcase", "http_methodeol",
                                    "http_unixeol"};
    for (size_t i = 0; i < NF(s); i++)
        T(b, P_HTTP " --lua-desync=%s", s[i]);
    return 1;
}

/* ---- 15-misc.sh ---------------------------------------------------------- */

static int s15(bc_run *b, const char *payload, const char *first)
{
    static const int reps[] = {1, 20, 100, 260};
    int ok = 0;
    for (size_t i = 0; i < NF(reps); i++) {
        if (T(b, "%s --lua-desync=tcpseg:pos=0,%s:ip_id=rnd:repeats=%d", payload, first, reps[i]))
            ok = 1;
        if (T(b, "%s --lua-desync=tcpseg:pos=0,midsld:ip_id=rnd:repeats=%d", payload, reps[i]))
            ok = 1;
        if (ok && !FORCE)
            break;
    }
    return ok;
}
static int s15_http(bc_run *b)
{
    return s15(b, P_HTTP, "method+2");
}
static int s15_tls(bc_run *b)
{
    return s15(b, P_TLS, "1");
}

/* ---- 17-oob.sh ----------------------------------------------------------- */

static int s17(bc_run *b)
{
    static const char *const urp[] = {"b", "0", "2", "midsld"};
    for (size_t i = 0; i < NF(urp); i++)
        T(b, "--in-range=-s1 --lua-desync=oob:urp=%s", urp[i]);
    return 1;
}

/* ---- 20-multi.sh --------------------------------------------------------- */

static const char *const splits_tls20[] = {"2",       "1",        "sniext+1", "sniext+4",          "host+1",
                                           "midsld",  "1,midsld", "1,midsld,1220",
                                           "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"};

static int s20_split(bc_run *b, const char *payload, const char *const *splits, size_t ns, const char *pre)
{
    int ok_any = 0;
    for (int k = 0; k < 2; k++) {
        const char *func = k ? mdis(b) : "multisplit";
        int *need = k ? &b->need_multidisorder : &b->need_multisplit, ok = 0;
        *need = 0;
        for (size_t i = 0; i < ns; i++)
            if (T(b, "%s %s --lua-desync=%s:pos=%s", pre, payload, func, splits[i]))
                ok = 1;
        if (!(ok && !FORCE))
            *need = 1;
        if (ok)
            ok_any = 1;
    }
    return ok_any;
}
static int s20_http(bc_run *b)
{
    return s20_split(b, P_HTTP, splits_http, NF(splits_http), "");
}
static int s20_tls(bc_run *b, const char *pre)
{
    return s20_split(b, P_TLS, splits_tls20, NF(splits_tls20), pre);
}
static int s20_tls12(bc_run *b)
{
    int ms, md;
    if (s20_tls(b, "") && !FORCE)
        return 1;
    /* do not use 'need' values obtained with wssize */
    ms = b->need_multisplit;
    md = b->need_multidisorder;
    s20_tls(b, WSSIZE);
    b->need_multisplit = ms;
    b->need_multidisorder = md;
    return 1;
}
static int s20_tls13(bc_run *b)
{
    return s20_tls(b, "");
}

/* ---- 23-seqovl.sh -------------------------------------------------------- */

static int s23_http(bc_run *b)
{
    static const char *const sp[] = {"method+2", "method+2,midsld"};
    static const char *const ds[][2] = {{"method+1", "method+2"}, {"midsld-1", "midsld"}, {"method+1", "method+2,midsld"}};
    const char *pat = "fake_default_http";
    int ok = 0;
    T(b, P_HTTP " --lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop");
    T(b, P_HTTP " --lua-desync=tcpseg:pos=0,-1:seqovl=#%s:seqovl_pattern=%s --lua-desync=drop", pat, pat);
    for (size_t i = 0; i < NF(sp); i++) {
        if (T(b, P_HTTP " --lua-desync=multisplit:pos=%s:seqovl=1", sp[i]))
            ok = 1;
        if (T(b, P_HTTP " --lua-desync=multisplit:pos=%s:seqovl=#%s:seqovl_pattern=%s", sp[i], pat, pat))
            ok = 1;
        if (ok && !FORCE)
            break;
    }
    for (size_t i = 0; i < NF(ds); i++) {
        T(b, P_HTTP " --lua-desync=%s:pos=%s:seqovl=%s", mdis(b), ds[i][1], ds[i][0]);
        T(b, P_HTTP " --lua-desync=%s:pos=%s:seqovl=%s:seqovl_pattern=%s", mdis(b), ds[i][1], ds[i][0], pat);
    }
    return 1;
}

static int s23_tls(bc_run *b, const char *pre)
{
    static const char *const sp[] = {"10", "10,sniext+1", "10,sniext+4", "10,midsld"};
    static const char *const ds[][2] = {
        {"1", "2"}, {"sniext", "sniext+1"}, {"sniext+3", "sniext+4"}, {"midsld-1", "midsld"}, {"1", "2,midsld"}};
    const char *pat = "fake_default_tls";
    char rnd[128], pad[192];
    int ok = 0, ok_any;
    snprintf(rnd, sizeof(rnd), "--lua-init=%s=tls_mod(%s,'rnd')", pat, pat);
    snprintf(pad, sizeof(pad),
             "--lua-desync=luaexec:code=desync.patmod=tls_mod(%s,'rnd,dupsid,padencap',desync.reasm_data)", pat);
    if (T(b, "%s " P_TLS " --lua-desync=tcpseg:pos=0,-1:seqovl=1 --lua-desync=drop", pre))
        ok = 1;
    if (T(b, "%s %s " P_TLS " --lua-desync=tcpseg:pos=0,-1:seqovl=#%s:seqovl_pattern=%s --lua-desync=drop", rnd, pre,
          pat, pat))
        ok = 1;
    if (T(b, "%s " P_TLS " %s --lua-desync=tcpseg:pos=0,-1:seqovl=#patmod:seqovl_pattern=patmod --lua-desync=drop",
          pre, pad))
        ok = 1;
    ok_any = ok;
    ok = 0;
    for (size_t i = 0; i < NF(sp); i++) {
        if (T(b, "%s " P_TLS " --lua-desync=multisplit:pos=%s:seqovl=1", pre, sp[i]))
            ok = 1;
        if (T(b, "%s %s " P_TLS " --lua-desync=multisplit:pos=%s:seqovl=#%s:seqovl_pattern=%s", rnd, pre, sp[i], pat,
              pat))
            ok = 1;
        if (T(b, "%s " P_TLS " %s --lua-desync=multisplit:pos=%s:seqovl=#patmod:seqovl_pattern=patmod", pre, pad,
              sp[i]))
            ok = 1;
        if (ok && !FORCE)
            break;
    }
    for (size_t i = 0; i < NF(ds); i++) {
        if (T(b, "%s " P_TLS " --lua-desync=%s:pos=%s:seqovl=%s", pre, mdis(b), ds[i][1], ds[i][0]))
            ok = 1;
        if (T(b, "%s %s " P_TLS " --lua-desync=%s:pos=%s:seqovl=%s:seqovl_pattern=%s", rnd, pre, mdis(b), ds[i][1],
              ds[i][0], pat))
            ok = 1;
    }
    if (ok)
        ok_any = 1;
    return ok_any;
}
static int s23_tls12(bc_run *b)
{
    if (s23_tls(b, "") && !FORCE)
        return 1;
    return s23_tls(b, WSSIZE);
}
static int s23_tls13(bc_run *b)
{
    return s23_tls(b, "");
}

/* ---- 24-syndata.sh ------------------------------------------------------- */

static int s24_http(bc_run *b)
{
    const char *sp[3] = {"", "multisplit", mdis(b)};
    for (int i = 0; i < 3; i++) {
        T(b, "--lua-desync=syndata %s%s", *sp[i] ? P_HTTP " --lua-desync=" : "", sp[i]);
        T(b, "--lua-desync=syndata:blob=fake_default_http %s%s", *sp[i] ? P_HTTP " --lua-desync=" : "", sp[i]);
    }
    return 1;
}
static int s24_tls(bc_run *b, const char *pre)
{
    static const char *const blobs[] = {"", ":blob=0x1603", ":blob=fake_default_tls:tls_mod=rnd,dupsid,rndsni",
                                        ":blob=fake_default_tls:tls_mod=rnd,dupsid,sni=google.com"};
    const char *sp[3] = {"", "multisplit", mdis(b)};
    int ok = 0;
    for (int i = 0; i < 3; i++)
        for (size_t j = 0; j < NF(blobs); j++)
            if (T(b, "%s --lua-desync=syndata%s %s%s", pre, blobs[j], *sp[i] ? P_TLS " --lua-desync=" : "", sp[i]))
                ok = 1;
    return ok;
}
static int s24_tls12(bc_run *b)
{
    if (s24_tls(b, "") && !FORCE)
        return 1;
    return s24_tls(b, WSSIZE);
}
static int s24_tls13(bc_run *b)
{
    return s24_tls(b, "");
}

/* ---- 25-fake.sh, 50-fake-multi.sh, 55-fake-faked.sh: the fakes of TLS ---- */

/* pktws_fake_https_vary_: the five fakes of a fooling; mid is what the
 * script puts after the fake (50: the split, 55: the faked split) */
typedef struct {
    const char *fake;   /* fake_default_tls */
    const char *splitf; /* 50, 55: the split function; NULL for 25 */
    const char *split;
    int faked;          /* 55: the split gets the fooling too */
} vary_ctx;

static int fake_https_vary_(bc_run *b, const vary_ctx *c, const char *fooling, const char *pre, const char *post,
                            int *ok)
{
    char mid[256] = "";
    int any = 0;
    if (c->splitf)
        snprintf(mid, sizeof(mid), "--lua-desync=%s:pos=%s%s%s", c->splitf, c->split, c->faked ? ":" : "",
                 c->faked ? fooling : "");
    any |= T(b, "%s " P_TLS " --lua-desync=fake:blob=%s:%s:repeats=%d %s %s", pre, c->fake, fooling, FR, mid, post);
    if (any && VQ)
        return *ok = 1;
    any |= T(b, "%s " P_TLS " --lua-desync=fake:blob=0x00000000:%s:repeats=%d %s %s", pre, fooling, FR, mid, post);
    if (any && VQ)
        return *ok = 1;
    any |= T(b,
             "%s " P_TLS " --lua-desync=fake:blob=0x00000000:%s:repeats=%d --lua-desync=fake:blob=%s:%s:"
             "tls_mod=rnd,dupsid:repeats=%d %s %s",
             pre, fooling, FR, c->fake, fooling, FR, mid, post);
    if (any && VQ)
        return *ok = 1;
    any |= T(b, "%s " P_TLS " --lua-desync=multisplit:blob=%s:%s:pos=2:nodrop:repeats=%d %s %s", pre, c->fake,
             fooling, FR, mid, post);
    if (any && VQ)
        return *ok = 1;
    any |= T(b, "%s " P_TLS " --lua-desync=fake:blob=%s:%s:tls_mod=rnd,dupsid,padencap:repeats=%d %s %s", pre,
             c->fake, fooling, FR, mid, post);
    if (any)
        *ok = 1;
    return any;
}

/* pktws_fake_https_vary: again with the MD5 SYN when the fooling is md5 */
static int fake_https_vary(bc_run *b, const vary_ctx *c, const char *fooling, const char *pre, const char *post,
                           int *ok)
{
    int any = fake_https_vary_(b, c, fooling, pre, post, ok);
    if (md5(fooling)) {
        char p2[512];
        snprintf(p2, sizeof(p2), "%s%s" MD5SEND, post, *post ? " " : "");
        any |= fake_https_vary_(b, c, fooling, pre, p2, ok);
    }
    return any;
}

/* ---- 25-fake.sh ---------------------------------------------------------- */

static int s25_http(bc_run *b)
{
    const char *ffs[2] = {"fake_default_http", "0x00000000"};
    char t[64];
    int ok = 0;
    FS(f);
    b->need_fake = 0;
    TTLS(ttl)
    {
        for (int i = 0; i < 2; i++)
            for (int j = 0; j < 2; j++)
                if (T(b, P_HTTP " --lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d %s", ffs[i], V, ttl, FR, fs[j])) {
                    ok = 1;
                    if (!FORCE)
                        break;
                }
        if (ok)
            break;
    }
    for (size_t k = 0; k < nfool(b); k++) {
        for (int i = 0; i < 2; i++) {
            if (T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d", ffs[i], fool(k), FR))
                ok = 1;
            if (md5(fool(k)) && T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d " MD5SEND, ffs[i], fool(k), FR))
                ok = 1;
            if (VQ && ok)
                break;
        }
        if (VQ && ok)
            break;
    }
    ATTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
        for (int i = 0; i < 2; i++)
            for (int j = 0; j < 2; j++)
                if (T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d %s", ffs[i], t, FR, fs[j])) {
                    ok = 1;
                    if (!FORCE)
                        break;
                }
        if (VQ && ok)
            break;
    }
    if (!ok && !FORCE)
        b->need_fake = 1;
    return ok;
}

static int s25_tls(bc_run *b, const char *pre)
{
    vary_ctx c = {"fake_default_tls", NULL, NULL, 0};
    char t[64];
    int ok = 0;
    FS(f);
    b->need_fake = 0;
    TTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_ttl=%d", V, ttl);
        for (int j = 0; j < 2; j++)
            if (fake_https_vary(b, &c, t, pre, fs[j], &ok) && !FORCE)
                break;
        if (ok)
            break;
    }
    for (size_t k = 0; k < nfool(b); k++) {
        fake_https_vary(b, &c, fool(k), pre, "", &ok);
        if (VQ && ok)
            break;
    }
    ATTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
        for (int j = 0; j < 2; j++)
            if (fake_https_vary(b, &c, t, pre, fs[j], &ok) && !FORCE)
                break;
        if (VQ && ok)
            break;
    }
    if (!ok && !FORCE)
        b->need_fake = 1;
    return ok;
}
static int s25_tls12(bc_run *b)
{
    int nf;
    if (s25_tls(b, "") && !FORCE)
        return 1;
    nf = b->need_fake;
    s25_tls(b, WSSIZE);
    b->need_fake = nf;
    return 1;
}
static int s25_tls13(bc_run *b)
{
    return s25_tls(b, "");
}

/* ---- 30-faked.sh --------------------------------------------------------- */

static const char *const splits_tls30[] = {"2",      "1",        "sniext+1", "sniext+4", "host+1",
                                           "midsld", "1,midsld", "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1"};

static int s30_faked(bc_run *b, const char *payload, const char *const *splits, size_t ns, const char *pre)
{
    const char *splitfs[2];
    size_t nsf = 0;
    char t[64];
    int ok_any = 0;
    FS(f);
    if (!(b->need_multisplit == 0 && !FORCE))
        splitfs[nsf++] = "fakedsplit";
    if (!(b->need_multidisorder == 0 && !FORCE))
        splitfs[nsf++] = "fakeddisorder";
    for (size_t s = 0; s < nsf; s++) {
        int ok = 0;
        TTLS(ttl)
        {
            for (size_t i = 0; i < ns; i++) {
                for (int j = 0; j < 2; j++)
                    if (T(b, "%s %s --lua-desync=%s:pos=%s:ip%s_ttl=%d:repeats=%d %s", pre, payload, splitfs[s],
                          splits[i], V, ttl, FR, fs[j])) {
                        ok = 1;
                        if (!FORCE)
                            break;
                    }
                if (VQ && ok)
                    break;
            }
            if (ok)
                break;
        }
        for (size_t k = 0; k < nfool(b); k++) {
            for (size_t i = 0; i < ns; i++) {
                if (T(b, "%s %s --lua-desync=%s:pos=%s:%s", pre, payload, splitfs[s], splits[i], fool(k)))
                    ok = 1;
                if (md5(fool(k)) && T(b, "%s %s --lua-desync=%s:pos=%s:%s:repeats=%d " MD5SEND, pre, payload,
                                      splitfs[s], splits[i], fool(k), FR))
                    ok = 1;
                if (VQ && ok)
                    break;
            }
            if (VQ && ok)
                break;
        }
        ATTLS(ttl)
        {
            snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
            for (size_t i = 0; i < ns; i++) {
                for (int j = 0; j < 2; j++)
                    if (T(b, "%s %s --lua-desync=%s:pos=%s:%s:repeats=%d %s", pre, payload, splitfs[s], splits[i], t,
                          FR, fs[j])) {
                        ok = 1;
                        if (!FORCE)
                            break;
                    }
                if (VQ && ok)
                    break;
            }
            if (VQ && ok)
                break;
        }
        if (!ok && !FORCE) {
            if (!strcmp(splitfs[s], "fakedsplit"))
                b->need_fakedsplit = 1;
            else
                b->need_fakeddisorder = 1;
        }
        if (ok)
            ok_any = 1;
        if (VQ && ok_any)
            break;
    }
    return ok_any;
}
static int s30_http(bc_run *b)
{
    return s30_faked(b, P_HTTP, splits_http, NF(splits_http), "");
}
static int s30_tls(bc_run *b, const char *pre)
{
    return s30_faked(b, P_TLS, splits_tls30, NF(splits_tls30), pre);
}
static int s30_tls12(bc_run *b)
{
    int fs, fd;
    if (s30_tls(b, "") && !FORCE)
        return 1;
    fs = b->need_fakedsplit;
    fd = b->need_fakeddisorder;
    s30_tls(b, WSSIZE);
    b->need_fakedsplit = fs;
    b->need_fakeddisorder = fd;
    return 1;
}
static int s30_tls13(bc_run *b)
{
    return s30_tls(b, "");
}

/* ---- 35-hostfake.sh ------------------------------------------------------ */

static const char *const hf_mods[] = {"", "nofake1:", "nofake2:", "midhost=midsld:", "nofake1:midhost=midsld:",
                                      "nofake2:midhost=midsld:"};
static const char *const hf_dis[] = {"", "disorder_after:"};

static int hostfake35_vary_(bc_run *b, const char *payload, const char *fooling, const char *pre, const char *post,
                            int *ok)
{
    int any = 0;
    for (size_t d = 0; d < NF(hf_dis); d++)
        for (size_t m = 0; m < NF(hf_mods); m++) {
            any |= T(b, "%s %s --lua-desync=hostfakesplit:%s%s%s:repeats=%d %s", pre, payload, hf_dis[d], hf_mods[m],
                     fooling, FR, post);
            if (any && VQ)
                return *ok = 1;
        }
    if (any)
        *ok = 1;
    return any;
}
static int hostfake35_vary(bc_run *b, const char *payload, const char *fooling, const char *pre, const char *post,
                           int *ok)
{
    int any = hostfake35_vary_(b, payload, fooling, pre, post, ok);
    if (md5(fooling)) {
        char p2[512];
        snprintf(p2, sizeof(p2), "%s%s" MD5SEND, post, *post ? " " : "");
        any |= hostfake35_vary_(b, payload, fooling, pre, p2, ok);
    }
    return any;
}
static int s35_hostfake(bc_run *b, const char *payload, const char *pre)
{
    char t[64];
    int ok = 0;
    FS(f);
    b->need_hostfakesplit = 0;
    TTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_ttl=%d", V, ttl);
        for (int j = 0; j < 2; j++)
            if (hostfake35_vary(b, payload, t, pre, fs[j], &ok) && !FORCE)
                break;
        if (ok)
            break;
    }
    for (size_t k = 0; k < nfool(b); k++) {
        hostfake35_vary(b, payload, fool(k), pre, "", &ok);
        if (VQ && ok)
            break;
    }
    ATTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
        for (int j = 0; j < 2; j++)
            if (hostfake35_vary(b, payload, t, pre, fs[j], &ok) && !FORCE)
                break;
        if (VQ && ok)
            break;
    }
    if (!ok && !FORCE)
        b->need_hostfakesplit = 1;
    return ok;
}
static int s35_http(bc_run *b)
{
    return s35_hostfake(b, P_HTTP, "");
}
static int s35_tls12(bc_run *b)
{
    int nh;
    if (s35_hostfake(b, P_TLS, "") && !FORCE)
        return 1;
    nh = b->need_hostfakesplit;
    s35_hostfake(b, P_TLS, WSSIZE);
    b->need_hostfakesplit = nh;
    return 1;
}
static int s35_tls13(bc_run *b)
{
    return s35_hostfake(b, P_TLS, "");
}

/* ---- 50-fake-multi.sh ---------------------------------------------------- */

static int s50_http(bc_run *b)
{
    const char *ffs[2] = {"fake_default_http", "0x00000000"};
    const char *splitfs[2];
    size_t nsf = 0;
    char t[64];
    FS(f);
    if (!(b->need_multisplit == 0 && !FORCE))
        splitfs[nsf++] = "multisplit";
    if (!(b->need_multidisorder == 0 && !FORCE))
        splitfs[nsf++] = mdis(b);
    for (size_t s = 0; s < nsf; s++) {
        int ok = 0;
        TTLS(ttl)
        {
            for (size_t i = 0; i < NF(splits_http); i++)
                for (int k = 0; k < 2; k++)
                    for (int j = 0; j < 2; j++)
                        if (T(b, P_HTTP " --lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d --lua-desync=%s:pos=%s %s",
                              ffs[k], V, ttl, FR, splitfs[s], splits_http[i], fs[j])) {
                            ok = 1;
                            if (!FORCE)
                                break;
                        }
            if (ok)
                break;
        }
        for (size_t q = 0; q < nfool(b); q++)
            for (size_t i = 0; i < NF(splits_http); i++)
                for (int k = 0; k < 2; k++) {
                    if (T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=%s:pos=%s", ffs[k],
                          fool(q), FR, splitfs[s], splits_http[i]))
                        ok = 1;
                    if (md5(fool(q)) && T(b,
                                          P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=%s:pos=%s "
                                                 MD5SEND,
                                          ffs[k], fool(q), FR, splitfs[s], splits_http[i]))
                        ok = 1;
                }
        ATTLS(ttl)
        {
            snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
            for (size_t i = 0; i < NF(splits_http); i++)
                for (int k = 0; k < 2; k++)
                    for (int j = 0; j < 2; j++)
                        if (T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=%s:pos=%s %s", ffs[k],
                              t, FR, splitfs[s], splits_http[i], fs[j])) {
                            ok = 1;
                            if (!FORCE)
                                break;
                        }
        }
    }
    return 1;
}

/* the TLS part of 50 and 55: splitfs and splits differ */
static int fake_split_tls(bc_run *b, const char *const *splitfs, size_t nsf, const char *const *splits, size_t ns,
                          int faked, const char *pre)
{
    char t[64];
    int ok_any = 0;
    FS(f);
    for (size_t s = 0; s < nsf; s++) {
        vary_ctx c = {"fake_default_tls", splitfs[s], NULL, faked};
        int ok = 0;
        TTLS(ttl)
        {
            snprintf(t, sizeof(t), "ip%s_ttl=%d", V, ttl);
            for (size_t i = 0; i < ns; i++) {
                c.split = splits[i];
                for (int j = 0; j < 2; j++)
                    if (fake_https_vary(b, &c, t, pre, fs[j], &ok) && !FORCE)
                        break;
                if (VQ && ok)
                    break;
            }
            if (ok)
                break;
        }
        for (size_t q = 0; q < nfool(b); q++) {
            for (size_t i = 0; i < ns; i++) {
                c.split = splits[i];
                fake_https_vary(b, &c, fool(q), pre, "", &ok);
                if (VQ && ok)
                    break;
            }
            if (VQ && ok)
                break;
        }
        ATTLS(ttl)
        {
            snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
            for (size_t i = 0; i < ns; i++) {
                c.split = splits[i];
                for (int j = 0; j < 2; j++)
                    if (fake_https_vary(b, &c, t, pre, fs[j], &ok) && !FORCE)
                        break;
                if (VQ && ok)
                    break;
            }
            if (VQ && ok)
                break;
        }
        if (ok)
            ok_any = 1;
        if (VQ && ok_any)
            break;
    }
    return ok_any;
}

static int s50_tls(bc_run *b, const char *pre)
{
    const char *splitfs[2];
    size_t nsf = 0;
    if (!(b->need_multisplit == 0 && !FORCE))
        splitfs[nsf++] = "multisplit";
    if (!(b->need_multidisorder == 0 && !FORCE))
        splitfs[nsf++] = mdis(b);
    return fake_split_tls(b, splitfs, nsf, splits_tls20, NF(splits_tls20), 0, pre);
}
static int s50_tls12(bc_run *b)
{
    if (s50_tls(b, "") && !FORCE)
        return 1;
    return s50_tls(b, WSSIZE);
}
static int s50_tls13(bc_run *b)
{
    return s50_tls(b, "");
}

/* ---- 55-fake-faked.sh ---------------------------------------------------- */

static size_t faked_splitfs(const bc_run *b, const char **splitfs)
{
    size_t n = 0;
    if (!(b->need_fakedsplit == 0 && !FORCE))
        splitfs[n++] = "fakedsplit";
    if (!(b->need_fakeddisorder == 0 && !FORCE))
        splitfs[n++] = "fakeddisorder";
    return n;
}

static int s55_http(bc_run *b)
{
    const char *ffs[2] = {"fake_default_http", "0x00000000"};
    const char *splitfs[2];
    size_t nsf = faked_splitfs(b, splitfs);
    char t[64];
    FS(f);
    for (size_t s = 0; s < nsf; s++) {
        int ok = 0;
        TTLS(ttl)
        {
            for (size_t i = 0; i < NF(splits_http); i++) {
                for (int k = 0; k < 2; k++)
                    for (int j = 0; j < 2; j++)
                        if (T(b,
                              P_HTTP " --lua-desync=fake:blob=%s:ip%s_ttl=%d:repeats=%d --lua-desync=%s:pos=%s:"
                                     "ip%s_ttl=%d:repeats=%d %s",
                              ffs[k], V, ttl, FR, splitfs[s], splits_http[i], V, ttl, FR, fs[j])) {
                            ok = 1;
                            if (!FORCE)
                                break;
                        }
                if (VQ && ok)
                    break;
            }
            if (ok)
                break;
        }
        for (size_t q = 0; q < nfool(b); q++) {
            for (size_t i = 0; i < NF(splits_http); i++) {
                for (int k = 0; k < 2; k++) {
                    if (T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=%s:pos=%s:%s:repeats=%d",
                          ffs[k], fool(q), FR, splitfs[s], splits_http[i], fool(q), FR))
                        ok = 1;
                    if (md5(fool(q)) &&
                        T(b,
                          P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=%s:pos=%s:%s:repeats=%d " MD5SEND,
                          ffs[k], fool(q), FR, splitfs[s], splits_http[i], fool(q), FR))
                        ok = 1;
                }
                if (VQ && ok)
                    break;
            }
            if (VQ && ok)
                break;
        }
        ATTLS(ttl)
        {
            snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
            for (size_t i = 0; i < NF(splits_http); i++) {
                for (int k = 0; k < 2; k++)
                    for (int j = 0; j < 2; j++)
                        if (T(b, P_HTTP " --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=%s:pos=%s:%s:repeats=%d %s",
                              ffs[k], t, FR, splitfs[s], splits_http[i], t, FR, fs[j])) {
                            ok = 1;
                            if (!FORCE)
                                break;
                        }
                if (VQ && ok)
                    break;
            }
            if (VQ && ok)
                break;
        }
        if (VQ && ok)
            break;
    }
    return 1;
}

static int s55_tls(bc_run *b, const char *pre)
{
    const char *splitfs[2];
    size_t nsf = faked_splitfs(b, splitfs);
    return fake_split_tls(b, splitfs, nsf, splits_tls30, NF(splits_tls30), 1, pre);
}
static int s55_tls12(bc_run *b)
{
    if (s55_tls(b, "") && !FORCE)
        return 1;
    return s55_tls(b, WSSIZE);
}
static int s55_tls13(bc_run *b)
{
    return s55_tls(b, "");
}

/* ---- 60-fake-hostfake.sh ------------------------------------------------- */

/* sets the caller's ok and returns success only on veryquick's early way
 * out, as the shell function's status does */
static int hostfake60_vary_(bc_run *b, const char *payload, const char *fake, const char *fooling, const char *pre,
                            const char *post, int *ok)
{
    for (size_t d = 0; d < NF(hf_dis); d++)
        for (size_t m = 0; m < NF(hf_mods); m++) {
            if (T(b, "%s %s --lua-desync=fake:blob=%s:%s:repeats=%d --lua-desync=hostfakesplit:%s%s%s:repeats=%d %s",
                  pre, payload, fake, fooling, FR, hf_dis[d], hf_mods[m], fooling, FR, post))
                *ok = 1;
            if (*ok && VQ)
                return 1;
        }
    return 0;
}
static int hostfake60_vary(bc_run *b, const char *payload, const char *fake, const char *fooling, const char *pre,
                           const char *post, int *ok)
{
    char p2[512];
    hostfake60_vary_(b, payload, fake, fooling, pre, post, ok);
    if (!md5(fooling))
        return 0;
    snprintf(p2, sizeof(p2), "%s%s" MD5SEND, post, *post ? " " : "");
    return hostfake60_vary_(b, payload, fake, fooling, pre, p2, ok);
}
static int s60_hostfake(bc_run *b, const char *payload, const char *fake, const char *pre)
{
    char t[64];
    int ok = 0;
    FS(f);
    if (b->need_hostfakesplit == 0)
        return 1;
    TTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_ttl=%d", V, ttl);
        for (int j = 0; j < 2; j++)
            if (hostfake60_vary(b, payload, fake, t, pre, fs[j], &ok)) {
                ok = 1;
                if (!FORCE)
                    break;
            }
        if (ok)
            break;
    }
    for (size_t k = 0; k < nfool(b); k++) {
        if (hostfake60_vary(b, payload, fake, fool(k), pre, "", &ok))
            ok = 1;
        if (VQ && ok)
            break;
    }
    ATTLS(ttl)
    {
        snprintf(t, sizeof(t), "ip%s_autottl=-%d,3-20", V, ttl);
        for (int j = 0; j < 2; j++)
            if (hostfake60_vary(b, payload, fake, t, pre, fs[j], &ok)) {
                ok = 1;
                if (!FORCE)
                    break;
            }
        if (VQ && ok)
            break;
    }
    return ok;
}
static int s60_http(bc_run *b)
{
    return s60_hostfake(b, P_HTTP, "fake_default_http", "");
}
static int s60_tls12(bc_run *b)
{
    if (s60_hostfake(b, P_TLS, "fake_default_tls", "") && !FORCE)
        return 1;
    return s60_hostfake(b, P_TLS, "fake_default_tls", WSSIZE);
}
static int s60_tls13(bc_run *b)
{
    return s60_hostfake(b, P_TLS, "fake_default_tls", "");
}

/* ---- 90-quic.sh ---------------------------------------------------------- */

static int s90_http3(bc_run *b)
{
    static const int reps[] = {1, 2, 5, 10, 20}, pos[] = {8, 16, 32, 64};
    static const char *const f6[] = {"ip6_hopbyhop", "ip6_destopt", "ip6_hopbyhop:ip6_destopt"};
    const char *P = "--payload=quic_initial", *fake = "fake_default_quic";
    for (size_t i = 0; i < NF(reps); i++)
        if (T(b, "%s --lua-desync=fake:blob=%s:repeats=%d", P, fake, reps[i]) && !FORCE)
            break;
    if (b->ipv == 6)
        for (size_t i = 0; i < NF(f6); i++)
            T(b, "%s --lua-desync=send:%s --lua-desync=drop", P, f6[i]);
    for (size_t i = 0; i < NF(pos); i++)
        if (T(b, "%s --lua-desync=send:ipfrag:ipfrag_pos_udp=%d --lua-desync=drop", P, pos[i]) && !FORCE)
            break;
    for (size_t i = 0; i < NF(pos); i++)
        if (T(b, "%s --lua-desync=fake:blob=%s:repeats=%d --lua-desync=send:ipfrag:ipfrag_pos_udp=%d --lua-desync=drop",
              P, fake, FR, pos[i]) &&
            !FORCE)
            break;
    return 1;
}

/* ---- test_runner ---------------------------------------------------------- */

typedef int (*script_fn)(bc_run *b);

static const struct {
    const char *name;
    script_fn fn[BC_NTESTS]; /* http, tls12, tls13, http3 */
} scripts[] = {
    {"10-http-basic.sh", {s10_http, NULL, NULL, NULL}},
    {"15-misc.sh", {s15_http, s15_tls, s15_tls, NULL}},
    {"17-oob.sh", {s17, s17, s17, NULL}},
    {"20-multi.sh", {s20_http, s20_tls12, s20_tls13, NULL}},
    {"23-seqovl.sh", {s23_http, s23_tls12, s23_tls13, NULL}},
    {"24-syndata.sh", {s24_http, s24_tls12, s24_tls13, NULL}},
    {"25-fake.sh", {s25_http, s25_tls12, s25_tls13, NULL}},
    {"30-faked.sh", {s30_http, s30_tls12, s30_tls13, NULL}},
    {"35-hostfake.sh", {s35_http, s35_tls12, s35_tls13, NULL}},
    {"50-fake-multi.sh", {s50_http, s50_tls12, s50_tls13, NULL}},
    {"55-fake-faked.sh", {s55_http, s55_tls12, s55_tls13, NULL}},
    {"60-fake-hostfake.sh", {s60_http, s60_tls12, s60_tls13, NULL}},
    {"90-quic.sh", {NULL, NULL, NULL, s90_http3}},
};

int bc_select_scripts(bc_run *b, const char *list, sbuf *err)
{
    const char *p = list;
    b->skip = ~0u;
    while (*p) {
        size_t n = strcspn(p, ","), i;
        for (i = 0; i < NF(scripts); i++)
            if (n && !strncmp(scripts[i].name, p, n) && scripts[i].name[n] == '-')
                break;
        if (i == NF(scripts)) {
            sb_printf(err, "no script %.*s (10, 15, 17, 20, 23, 24, 25, 30, 35, 50, 55, 60, 90)", (int)n, p);
            return -1;
        }
        b->skip &= ~(1u << i);
        p += n + (p[n] == ',');
    }
    return 0;
}

int bc_scripts(bc_run *b, int test, const char *domain, int ipv)
{
    if (test < 0 || test >= BC_NTESTS)
        return -1;
    b->testf = test_names[test];
    b->domain = domain;
    b->ipv = ipv;
    free(b->strategy);
    b->strategy = NULL;
    for (size_t i = 0; i < NF(scripts) && !b->stopped; i++) {
        if (!scripts[i].fn[test] || (b->skip >> i & 1))
            continue;
        if (b->log)
            fprintf(b->log, "\n* script : standard/%s\n", scripts[i].name);
        scripts[i].fn[test](b);
    }
    if (b->stopped)
        return -1;
    /* report_strategy */
    if (b->strategy) {
        if (b->log)
            fprintf(b->log, "\n!!!!! %s: working strategy found for ipv%d %s : nfqws2 %s !!!!!\n\n", b->testf, ipv,
                    domain, b->strategy);
        return 1;
    }
    if (b->log)
        fprintf(b->log, "\n%s: nfqws2 strategy for ipv%d %s not found\n\n", b->testf, ipv, domain);
    bc_report(b, domain, "nfqws2 not working", NULL);
    return 0;
}

/* ---- the report ----------------------------------------------------------- */

typedef struct {
    const char *key, *gen;
    size_t count;
} bc_hash;

/* report_append's hash of "TEST ipvN : VALUE", in order of appearance */
static bc_hash *hashes(const bc_run *b, size_t *n)
{
    bc_hash *h = NULL;
    *n = 0;
    for (size_t i = 0; i < b->nrep; i++) {
        size_t j;
        for (j = 0; j < *n && strcmp(h[j].key, b->rep[i].key); j++)
            ;
        if (j == *n) {
            h = xrealloc(h, (*n + 1) * sizeof(*h));
            h[j].key = b->rep[i].key;
            h[j].gen = b->rep[i].gen;
            h[j].count = 0;
            (*n)++;
        }
        h[j].count++;
    }
    return h;
}

/* sort -rn: the count down, then the line backwards (the last resort of a
 * reversed sort) */
static int by_coverage(const void *pa, const void *pb)
{
    const bc_hash *a = pa, *b = pb;
    if (a->count != b->count)
        return a->count < b->count ? 1 : -1;
    return -strcmp(a->key, b->key);
}

void bc_print(const bc_run *b, int ndomains, FILE *out)
{
    size_t nh;
    bc_hash *h;
    fprintf(out, "\n* SUMMARY\n");
    for (size_t i = 0; i < b->nrep; i++) {
        fprintf(out, "%s\n", b->rep[i].line);
        if (b->rep[i].gen)
            fprintf(out, "  geneva: %s\n", b->rep[i].gen);
    }
    if (ndomains <= 1)
        return;
    h = hashes(b, &nh);
    fprintf(out, "\n* COMMON\n");
    for (size_t i = 0; i < nh; i++)
        if (h[i].count == (size_t)ndomains) {
            fprintf(out, "%s\n", h[i].key);
            if (h[i].gen)
                fprintf(out, "  geneva: %s\n", h[i].gen);
        }
    qsort(h, nh, sizeof(*h), by_coverage);
    fprintf(out, "\n* COVERAGE\n");
    for (size_t i = 0; i < nh; i++) {
        fprintf(out, "%zu/%d : %s\n", h[i].count, ndomains, h[i].key);
        if (h[i].gen)
            fprintf(out, "  geneva: %s\n", h[i].gen);
    }
    if (b->level != BC_FORCE)
        fprintf(out, "\nblockcheck optimizes test sequence. To save time some strategies can be skipped if their test "
                     "is considered useless.\nThat's why COMMON intersection can miss strategies that would work for "
                     "all domains, and COVERAGE counts can undercount.\nUse \"force\" scan level to test all "
                     "strategies and generate trustable results.\n");
    free(h);
}

static void j_entry(jw *w, const char *test, const char *value, const char *gen)
{
    jw_kstr(w, "test", test);
    if (!strncmp(value, "nfqws2 ", 7) && gen) {
        jw_kstr(w, "nfqws2", value + 7);
        jw_kstr(w, "strategy", gen);
    } else {
        jw_kstr(w, "result", value);
    }
}

void bc_print_json(const bc_run *b, int ndomains, sbuf *out)
{
    static const char *const lv[] = {"veryquick", "quick", "standard", "force"};
    jw w;
    size_t nh;
    bc_hash *h = hashes(b, &nh);
    jw_init(&w, out);
    jw_obj(&w);
    jw_kstr(&w, "level", lv[b->level]);
    jw_kint(&w, "domains", ndomains);
    jw_kint(&w, "tests", b->ntests);
    jw_key(&w, "summary");
    jw_arr(&w);
    for (size_t i = 0; i < b->nrep; i++) {
        jw_obj(&w);
        jw_kstr(&w, "domain", b->rep[i].domain);
        j_entry(&w, b->rep[i].test, b->rep[i].value, b->rep[i].gen);
        jw_obj_end(&w);
    }
    jw_arr_end(&w);
    jw_key(&w, "common");
    jw_arr(&w);
    for (size_t i = 0; ndomains > 1 && i < nh; i++)
        if (h[i].count == (size_t)ndomains) {
            const char *sep = strstr(h[i].key, " : ");
            sbuf t;
            sb_init(&t);
            sb_append(&t, h[i].key, (size_t)(sep - h[i].key));
            jw_obj(&w);
            j_entry(&w, t.data, sep + 3, h[i].gen);
            jw_obj_end(&w);
            sb_free(&t);
        }
    jw_arr_end(&w);
    qsort(h, nh, sizeof(*h), by_coverage);
    jw_key(&w, "coverage");
    jw_arr(&w);
    for (size_t i = 0; ndomains > 1 && i < nh; i++) {
        const char *sep = strstr(h[i].key, " : ");
        sbuf t;
        sb_init(&t);
        sb_append(&t, h[i].key, (size_t)(sep - h[i].key));
        jw_obj(&w);
        jw_kint(&w, "count", (int64_t)h[i].count);
        j_entry(&w, t.data, sep + 3, h[i].gen);
        jw_obj_end(&w);
        sb_free(&t);
    }
    jw_arr_end(&w);
    jw_obj_end(&w);
    free(h);
}
