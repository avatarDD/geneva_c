/* Stage X6b: lists of the profiles: inflate (src/ext/inflate.c), host
 * lists (hostlist.c), IP sets (ipset.c), the list files with their reload
 * (lists.c), and the profiles that use them (zapret2's dp_match order,
 * the rediscovery once the host name is known). */
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
#  include "ext/hostlist.h"
#  include "ext/inflate.h"
#  include "ext/ipset.h"
#  include "ext/lists.h"
#  include "ext/profile.h"
#  include "ext/xact.h"
#  include "ext/xtrig.h"

TEST(ls_inflate)
{
    static const uint8_t fixed[] = "\xcb\x48\xcd\xc9\xc9\x57\xc8\x40\x90\x5c\x00";
    static const uint8_t stored[] = "\x01\x07\x00\xf8\xff\x73\x74\x6f\x72\x65\x64\x21";
    static const uint8_t zl[] = "\x78\x9c\xab\xca\xc9\x4c\x52\x28\x2f\x4a\x2c\x28\x48\x4d\xe1\x02\x00\x23\xd3\x04\xcf";
    static const uint8_t gz[] = "\x1f\x8b\x08\x08\x00\x00\x00\x00\x02\xff\x6c\x69\x73\x74\x2e\x74\x78\x74\x00\x4b"
                                "\xd4\x4b\xe2\x4a\xd6\x4b\xe1\x02\x00\xc7\xff\x69\x13\x08\x00\x00\x00";
    uint8_t *out, bad[sizeof(gz)];
    size_t n, used;
    CHECK_INT(xinf_raw(fixed, 11, 100, &out, &n, &used), 0);
    CHECK_MEM(out, n, "hello hello hello\n", 18);
    CHECK_INT((int)used, 11);
    free(out);
    CHECK_INT(xinf_raw(stored, 12, 100, &out, &n, &used), 0);
    CHECK_MEM(out, n, "stored!", 7);
    free(out);
    CHECK_INT(xinf_unwrap(zl, 21, 100, &out, &n), 0);
    CHECK_MEM(out, n, "zlib wrapped\n", 13);
    free(out);
    CHECK(xinf_is_gzip(gz, sizeof(gz) - 1));
    CHECK(!xinf_is_gzip(zl, 21));
    CHECK_INT(xinf_unwrap(gz, sizeof(gz) - 1, 100, &out, &n), 0);
    CHECK_MEM(out, n, "a.b\nc.d\n", 8);
    free(out);
    /* the output limit */
    CHECK_INT(xinf_unwrap(gz, sizeof(gz) - 1, 7, &out, &n), -2);
    CHECK(out == NULL);
    CHECK_INT(xinf_unwrap(gz, sizeof(gz) - 1, 8, &out, &n), 0);
    free(out);
    /* every truncation is an error, never a read past the end */
    for (size_t k = 0; k < sizeof(gz) - 1; k++)
        CHECK_INT(xinf_unwrap(gz, k, 100, &out, &n), -1);
    for (size_t k = 0; k < 21; k++)
        CHECK_INT(xinf_unwrap(zl, k, 100, &out, &n), -1);
    /* a wrong CRC-32, length, Adler-32 */
    memcpy(bad, gz, sizeof(gz));
    bad[sizeof(gz) - 9] ^= 1;
    CHECK_INT(xinf_unwrap(bad, sizeof(gz) - 1, 100, &out, &n), -1);
    memcpy(bad, gz, sizeof(gz));
    bad[sizeof(gz) - 5] ^= 1;
    CHECK_INT(xinf_unwrap(bad, sizeof(gz) - 1, 100, &out, &n), -1);
    memcpy(bad, zl, 21);
    bad[20] ^= 1;
    CHECK_INT(xinf_unwrap(bad, 21, 100, &out, &n), -1);
    /* block type 3, a bad stored length */
    CHECK_INT(xinf_raw((const uint8_t *)"\x07", 1, 100, &out, &n, NULL), -1);
    CHECK_INT(xinf_raw((const uint8_t *)"\x01\x07\x00\xf8\xfe", 5, 100, &out, &n, NULL), -1);
    /* a distance before the start of the output: 0x63 0x00 is fixed,
     * then a match at distance 1 with nothing out yet */
    CHECK_INT(xinf_raw((const uint8_t *)"\x03\x02\x00", 3, 100, &out, &n, NULL), -1);
    CHECK(xinf_crc32(0, (const uint8_t *)"123456789", 9) == 0xcbf43926u);
    /* random bytes: errors or output, never a crash (ASan) */
    {
        uint32_t r = 12345;
        uint8_t b[256];
        for (int t = 0; t < 2000; t++) {
            for (size_t i = 0; i < sizeof(b); i++) {
                r = r * 1103515245u + 12345u;
                b[i] = (uint8_t)(r >> 16);
            }
            if (xinf_raw(b, (size_t)(t % 256), 4096, &out, &n, NULL) == 0)
                free(out);
        }
    }
}

TEST(ls_files_inflate)
{
    size_t pn, gn, zn, n;
    char *plain = read_file("tests/data/lists/hosts.txt", &pn);
    char *g = read_file("tests/data/lists/hosts.txt.gz", &gn);
    char *z = read_file("tests/data/lists/hosts.txt.z", &zn);
    uint8_t *out;
    CHECK(plain && g && z);
    if (plain && g && z) {
        CHECK_INT(xinf_unwrap((const uint8_t *)g, gn, 1 << 20, &out, &n), 0);
        CHECK_MEM(out, n, plain, pn);
        free(out);
        CHECK_INT(xinf_unwrap((const uint8_t *)z, zn, 1 << 20, &out, &n), 0);
        CHECK_MEM(out, n, plain, pn);
        free(out);
        /* a byte changed in the middle of a dynamic block */
        g[gn / 2] ^= 0x10;
        CHECK(xinf_unwrap((const uint8_t *)g, gn, 1 << 20, &out, &n) < 0);
    }
    free(plain);
    free(g);
    free(z);
}

TEST(ls_hostlist)
{
    xhostset h = {0};
    int ex;
    char b[64];
    const char *t = "  example.com\r\n# c\n; c\n/ c\n\n^strict.org\n!good.example.com\nUPPER.net tail\n^!both.io";
    CHECK_INT((int)xhs_parse(&h, t, strlen(t)), 5);
    CHECK_INT((int)h.n, 5);
    CHECK(xhs_search(&h, "example.com", 0, NULL));
    CHECK(xhs_search(&h, "www.example.com", 0, NULL));
    CHECK(!xhs_search(&h, "xexample.com", 0, NULL));
    CHECK(!xhs_search(&h, "com", 0, NULL));
    /* ^: the name only */
    CHECK(xhs_search(&h, "strict.org", 0, NULL));
    CHECK(!xhs_search(&h, "a.strict.org", 0, NULL));
    /* !: exempt, the search stops */
    CHECK(!xhs_search(&h, "good.example.com", 0, &ex));
    CHECK(ex);
    CHECK(!xhs_search(&h, "x.good.example.com", 0, &ex));
    CHECK(ex);
    CHECK(xhs_search(&h, "bad.example.com", 0, &ex));
    CHECK(!ex);
    CHECK(xhs_search(&h, "upper.net", 0, NULL));
    /* ^! on a subdomain: not this entry, the parents go on */
    CHECK(!xhs_search(&h, "a.both.io", 0, &ex));
    CHECK(!ex);
    CHECK(!xhs_search(&h, "both.io", 0, &ex));
    CHECK(ex);
    /* no_subdom (an IP address): the full name only */
    CHECK(!xhs_search(&h, "www.example.com", 1, NULL));
    /* the first entry of a name keeps its flags */
    xhs_add(&h, "STRICT.org", 10, 0);
    CHECK(!xhs_search(&h, "a.strict.org", 0, NULL));
    /* growth */
    for (int i = 0; i < 5000; i++) {
        snprintf(b, sizeof(b), "n%d.grow", i);
        xhs_add(&h, b, strlen(b), 0);
    }
    CHECK_INT((int)h.n, 5005);
    CHECK(xhs_search(&h, "x.n4999.grow", 0, NULL));
    CHECK(xhs_search(&h, "n0.grow", 0, NULL));
    CHECK(!xhs_search(&h, "grow", 0, NULL));
    xhs_free(&h);
    CHECK(!xhs_search(&h, "example.com", 0, NULL));
    /* strip_host_to_ip */
    CHECK_INT(xhost_norm("example.com:8080", b, sizeof(b)), 0);
    CHECK_STR(b, "example.com");
    CHECK_INT(xhost_norm("1.2.3.4:80", b, sizeof(b)), 1);
    CHECK_STR(b, "1.2.3.4");
    CHECK_INT(xhost_norm("[2a00::1]:443", b, sizeof(b)), 1);
    CHECK_STR(b, "2a00::1");
    CHECK_INT(xhost_norm("2a00::1", b, sizeof(b)), 1);
    CHECK_INT(xhost_norm("[x", b, sizeof(b)), 0);
    CHECK_INT(xhost_norm("a", b, sizeof(b)), 0);
}

static int has4(const xipset *s, const char *a)
{
    uint8_t b[16];
    return inet_pton(AF_INET, a, b) == 1 && xips_has(s, 4, b);
}

static int has6(const xipset *s, const char *a)
{
    uint8_t b[16];
    return inet_pton(AF_INET6, a, b) == 1 && xips_has(s, 6, b);
}

TEST(ls_ipset)
{
    xipset s = {0};
    size_t bad = 0;
    char first[32] = "";
    const char *t = "# c\n1.2.3.4\n10.0.0.0/8\n 192.168.1.7/16 # home\nbad\n2a00:1450::/32\n::1\n1.2.3.4/33\n"
                    "10.1.0.0/16\n";
    CHECK_INT((int)xips_parse(&s, t, strlen(t), &bad, first, sizeof(first)), 6);
    CHECK_INT((int)bad, 2);
    CHECK_STR(first, "bad");
    xips_finish(&s);
    CHECK_INT((int)s.n4, 3); /* 10.1/16 merged into 10/8 */
    CHECK(has4(&s, "1.2.3.4"));
    CHECK(!has4(&s, "1.2.3.5"));
    CHECK(!has4(&s, "1.2.3.3"));
    CHECK(has4(&s, "10.0.0.0"));
    CHECK(has4(&s, "10.255.255.255"));
    CHECK(!has4(&s, "11.0.0.0"));
    CHECK(!has4(&s, "9.255.255.255"));
    CHECK(has4(&s, "192.168.200.1")); /* host bits of the subnet ignored */
    CHECK(!has4(&s, "192.169.0.0"));
    CHECK(has6(&s, "2a00:1450:4001::1"));
    CHECK(!has6(&s, "2a00:1451::"));
    CHECK(has6(&s, "::1"));
    CHECK(!has6(&s, "::2"));
    CHECK(!has6(&s, "::"));
    xips_free(&s);
    /* /0 and the ends of the space */
    CHECK_INT(xips_add_str(&s, "0.0.0.0/0"), 0);
    CHECK_INT(xips_add_str(&s, "255.255.255.255"), 0);
    CHECK_INT(xips_add_str(&s, "::/0"), 0);
    CHECK_INT(xips_add_str(&s, "1.2.3.4/"), -1);
    CHECK_INT(xips_add_str(&s, "1.2.3.4/8x"), -1);
    CHECK_INT(xips_add_str(&s, "::1/129"), -1);
    xips_finish(&s);
    CHECK_INT((int)s.n4, 1);
    CHECK(has4(&s, "0.0.0.0") && has4(&s, "255.255.255.255"));
    CHECK(has6(&s, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"));
    xips_free(&s);
    /* /64 and /65 */
    CHECK_INT(xips_add_str(&s, "2001:db8::/64"), 0);
    CHECK_INT(xips_add_str(&s, "2001:db9:0:0:8000::/65"), 0);
    xips_finish(&s);
    CHECK(has6(&s, "2001:db8::ffff:ffff:ffff:ffff"));
    CHECK(!has6(&s, "2001:db8:0:1::"));
    CHECK(has6(&s, "2001:db9::ffff:0:0:0"));
    CHECK(!has6(&s, "2001:db9::7fff:0:0:0"));
    xips_free(&s);
}

static const char *tmp_list(const char *suffix, const char *text, size_t n)
{
    static char path[2][64];
    static int k;
    char *p = path[k++ & 1];
    snprintf(p, 64, "geneva-test-list-%d%s", (int)plat_getpid(), suffix);
    if (write_file(p, text, n) < 0)
        return NULL;
    return p;
}

TEST(ls_files)
{
    sbuf e;
    xlist *a, *b, *g;
    xlistref r = {0}, r2 = {0};
    const char *path;
    sb_init(&e);
    a = xlist_file("tests/data/lists/hosts.txt", 0, &e);
    CHECK(a != NULL);
    g = xlist_file("tests/data/lists/hosts.txt.gz", 0, &e);
    CHECK(g != NULL);
    if (a && g) {
        CHECK_INT((int)a->hs.n, 3004);
        CHECK_INT((int)g->hs.n, 3004);
        CHECK(xhs_search(&g->hs, "www.example.com", 0, NULL));
        CHECK(xhs_search(&g->hs, "upper.case.net", 0, NULL));
        /* one file, one list */
        b = xlist_file("./tests/data/lists/hosts.txt", 0, &e);
        CHECK(b == a);
        CHECK_INT(xlistref_add(&r, a), 0);
        CHECK_INT(xlistref_add(&r, a), -1);
        CHECK_INT(xlistref_add(&r, g), 0);
        xlistref_copy(&r2, &r);
        CHECK_INT((int)r2.n, 2);
        CHECK_INT(a->refs, 2);
    }
    xlistref_free(&r);
    xlistref_free(&r2);
    CHECK_INT((int)xlists_count(), 0);
    /* the IP set in gzip */
    {
        xlist *ip = xlist_file("tests/data/lists/ips.txt.gz", 1, &e);
        CHECK(ip != NULL);
        if (ip) {
            CHECK(has4(&ip->ips, "10.20.30.40"));
            CHECK(has6(&ip->ips, "2a00:1450::5"));
            xlistref_add(&r, ip);
            xlistref_free(&r);
        }
    }
    /* missing, bad gzip */
    sb_reset(&e);
    CHECK(xlist_file("geneva-no-such-list", 0, &e) == NULL);
    CHECK(strstr(e.data, "cannot access") != NULL);
    sb_reset(&e);
    path = tmp_list(".gz", "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xff\xff", 12);
    CHECK(path && xlist_file(path, 0, &e) == NULL);
    CHECK(strstr(e.data, "bad or truncated gzip") != NULL);
    if (path)
        remove(path);
    CHECK_INT((int)xlists_count(), 0);
    /* a plain file over several chunks, the last line without its end */
    {
        sbuf t;
        sb_init(&t);
        for (int i = 0; i < 12000; i++)
            sb_printf(&t, "%sn%05d.big", i ? "\n" : "", i);
        path = tmp_list(".txt", t.data, t.len);
        a = path ? xlist_file(path, 0, &e) : NULL;
        CHECK(a != NULL);
        if (a) {
            CHECK_INT((int)a->hs.n, 12000);
            CHECK(xhs_search(&a->hs, "n05957.big", 0, NULL));
            CHECK(xhs_search(&a->hs, "x.n11999.big", 0, NULL));
            xlistref_add(&r, a);
            xlistref_free(&r);
        }
        if (path)
            remove(path);
        sb_free(&t);
    }
    /* reload: on a change of size, on force; a failed load empties the
     * list and fails the profiles until the file loads again */
    path = tmp_list(".txt", "a.com\n", 6);
    a = path ? xlist_file(path, 0, &e) : NULL;
    CHECK(a != NULL);
    if (a) {
        xlistref_add(&r, a);
        CHECK_INT(xlists_reload(1000, 0), 0);
        write_file(path, "b.com\nc.com\n", 12);
        CHECK_INT(xlists_reload(1500, 0), 0); /* once a second at most */
        CHECK_INT(xlists_reload(2000, 0), 1);
        CHECK(xhs_search(&a->hs, "c.com", 0, NULL));
        CHECK(!xhs_search(&a->hs, "a.com", 0, NULL));
        CHECK_INT(xlists_reload(2100, 1), 1);
        write_file(path, "\x1f\x8b\x08\x00", 4);
        CHECK_INT(xlists_reload(3000, 0), 0);
        CHECK(a->failed && !a->hs.n);
        CHECK(!xlistref_ok(&r));
        write_file(path, "d.com\n", 6);
        CHECK_INT(xlists_reload(4000, 0), 1);
        CHECK(!a->failed && xlistref_ok(&r));
        /* gone: what was loaded stays */
        remove(path);
        CHECK_INT(xlists_reload(5000, 1), 0);
        CHECK(xhs_search(&a->hs, "d.com", 0, NULL));
        xlistref_free(&r);
    }
    sb_free(&e);
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

static void mt(xmatch *m, const char *ip, const char *host)
{
    static uint8_t a[16];
    memset(m, 0, sizeof(*m));
    m->ver = strchr(ip, ':') ? 6 : 4;
    inet_pton(m->ver == 6 ? AF_INET6 : AF_INET, ip, a);
    m->ip = a;
    m->proto = 6;
    m->port = 443;
    m->l7 = 1;
    m->host = host;
}

TEST(ls_profiles)
{
    xprofiles ps;
    xmatch m;
    {
        /* 1: hosts; 2: an IP set minus a subnet; 3: the rest */
        const char *v[] = {"--hostlist", "tests/data/lists/hosts.txt.gz", "--hostlist-exclude-domains",
                           "no.example.com,,", "-s", "\\/", "--new", "--ipset-ip", "10.0.0.0/8,2a00::/16",
                           "--ipset-exclude-ip", "10.9.0.0/16", "-s", "\\/", "--new", "-s", "\\/", NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 3);
        mt(&m, "1.1.1.1", "www.example.com");
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        mt(&m, "1.1.1.1", "no.example.com");
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        mt(&m, "1.1.1.1", "a.no.example.com");
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        mt(&m, "10.1.1.1", "good.example.com"); /* exempt */
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        /* no host yet: a profile with host lists cannot take it */
        mt(&m, "10.1.1.1", NULL);
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        CHECK_INT(xprof_find(&ps, &m, 1), 0); /* but it could later */
        mt(&m, "10.9.1.1", NULL);
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        mt(&m, "2a00::1", NULL);
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        mt(&m, "2a01::1", NULL);
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        /* the host name as an IP address: no parents */
        mt(&m, "1.1.1.1", "1.2.3.4");
        m.host_ip = 1;
        CHECK_INT(xprof_find(&ps, &m, 0), 2);
        xprof_free(&ps);
        CHECK_INT((int)xlists_count(), 0);
    }
    {
        /* an exclude list only: everything but it; an empty list file: as
         * if there were none (zapret2) */
        const char *empty = tmp_list(".txt", "# nothing\n", 10);
        const char *v[] = {"--hostlist-exclude-domains", "x.org", "-s", "\\/", "--new", "--hostlist",
                           empty ? empty : "-", "-s", "\\/", NULL};
        CHECK_STR(build(v, &ps), "OK");
        mt(&m, "1.1.1.1", "a.com");
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        mt(&m, "1.1.1.1", "x.org");
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        mt(&m, "1.1.1.1", NULL);
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        xprof_free(&ps);
        if (empty)
            remove(empty);
    }
    {
        /* import copies the lists; a file twice in a profile; skip */
        const char *v[] = {"--template=t", "--hostlist-domains", "t.org", "--new", "--import", "t", "-s", "\\/",
                           "--new", "--skip", "--hostlist", "no-such-file", "-s", "\\/", "--new", "-s", "\\/",
                           NULL};
        CHECK_STR(build(v, &ps), "OK");
        CHECK_INT((int)ps.n, 2);
        mt(&m, "1.1.1.1", "a.t.org");
        CHECK_INT(xprof_find(&ps, &m, 0), 0);
        mt(&m, "1.1.1.1", "a.com");
        CHECK_INT(xprof_find(&ps, &m, 0), 1);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--hostlist", "tests/data/lists/hosts.txt", "--hostlist", "tests/data/lists/hosts.txt",
                           "-s", "\\/", NULL};
        CHECK(strstr(build(v, &ps), "already in this profile") != NULL);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--ipset-ip", "1.2.3.4,x", "-s", "\\/", NULL};
        CHECK(strstr(build(v, &ps), "bad --ipset-ip item x") != NULL);
        xprof_free(&ps);
    }
    {
        const char *v[] = {"--ipset", "no-such-file", "-s", "\\/", NULL};
        CHECK(strstr(build(v, &ps), "cannot access no-such-file") != NULL);
        xprof_free(&ps);
    }
    CHECK_INT((int)xlists_count(), 0);
}

/* ---- the choice per packet ---------------------------------------------------- */

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

/* TCP between 10.0.0.2:40000 and 93.184.216.34:port */
static size_t mk(uint8_t *b, unsigned port, int in, uint8_t flags, uint32_t seq, const char *data)
{
    size_t dl = strlen(data), n = 40 + dl;
    static const uint8_t cli[4] = {10, 0, 0, 2}, srv[4] = {93, 184, 216, 34};
    memset(b, 0, 40);
    b[0] = 0x45;
    put16(b + 2, (unsigned)n);
    b[8] = 64;
    b[9] = 6;
    memcpy(b + 12, in ? srv : cli, 4);
    memcpy(b + 16, in ? cli : srv, 4);
    put16(b + 20, in ? port : 40000);
    put16(b + 22, in ? 40000 : port);
    put32(b + 24, seq);
    b[32] = 0x50;
    b[33] = flags;
    put16(b + 34, 65535);
    memcpy(b + 40, data, dl);
    return n;
}

static void rp(void *ud, const uint8_t *raw, size_t len, strat_dir dir, unsigned piece, unsigned pieces, void *xctx)
{
    (void)ud, (void)raw, (void)len, (void)dir, (void)piece, (void)pieces, (void)xctx;
}

static strategy *pick(xoffline *x, strategy *cmd, const uint8_t *b, size_t n, strat_dir dir, uint64_t t)
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

TEST(ls_pick)
{
    /* profile 1: hosts a.b and its subdomains (the command's strategy),
     * profile 2: an IP set with the server (its own); then nothing */
    const char *v[] = {"--ext", "-s", "\\/", "--filter-tcp", "80", "--hostlist-domains", "a.b",
                       "--new", "--filter-tcp", "80", "--ipset-ip", "93.184.216.0/24", "-s",
                       "[TCP:flags:S]-drop-| \\/", NULL};
    uint8_t b[200];
    size_t n;
    xoffline *x;
    strategy *cmd, *st;
    sbuf e;
    CHECK_INT(activate(v), 0);
    CHECK_INT((int)ext_profiles(), 2);
    sb_init(&e);
    cmd = strategy_parse("\\/", &e);
    sb_free(&e);
    x = xoff_new();
    if (!x || !cmd)
        goto out;
    /* the SYN: no host, profile 2 by the server's address */
    n = mk(b, 80, 0, 2, 1000, "");
    st = pick(x, cmd, b, n, DIR_OUT, 1);
    CHECK(st && st != cmd && st->nout == 1);
    /* the request names www.a.b: profile 1 takes the flow, and keeps it */
    n = mk(b, 80, 0, 24, 1001, "GET / HTTP/1.1\r\nHost: www.A.b:80\r\n\r\n");
    st = pick(x, cmd, b, n, DIR_OUT, 2);
    CHECK(st == cmd);
    n = mk(b, 80, 1, 24, 5000, "HTTP/1.1 200 OK\r\n\r\n");
    st = pick(x, cmd, b, n, DIR_IN, 3);
    CHECK(st == cmd);
    /* another flow, to another host: profile 2 still */
    n = mk(b, 80, 0, 2, 1000, "");
    b[21] ^= 1; /* another client port */
    st = pick(x, cmd, b, n, DIR_OUT, 4);
    CHECK(st && st != cmd);
    n = mk(b, 80, 0, 24, 1001, "GET / HTTP/1.1\r\nHost: c.d\r\n\r\n");
    b[21] ^= 1;
    st = pick(x, cmd, b, n, DIR_OUT, 5);
    CHECK(st && st != cmd);
    /* port 81: no profile */
    n = mk(b, 81, 0, 2, 1000, "");
    st = pick(x, cmd, b, n, DIR_OUT, 6);
    CHECK(st == NULL);
out:
    xoff_free(x);
    strategy_free(cmd);
    ext_reset();
    CHECK_INT((int)xlists_count(), 0);
}

void suite_lists(void)
{
    RUN(ls_inflate);
    RUN(ls_files_inflate);
    RUN(ls_hostlist);
    RUN(ls_ipset);
    RUN(ls_files);
    strategy_set_xact(&xact_ops);
    strategy_set_xtrig(&xtrig_ops);
    RUN(ls_profiles);
    strategy_set_xtrig(NULL);
    strategy_set_xact(NULL);
    RUN(ls_pick);
}

#else
void suite_lists(void) {}
#endif
