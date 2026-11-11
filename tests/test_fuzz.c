/* Stage X7c: the fuzz targets (src/ext/fuzz.c), "geneva selftest --ext"
 * and what fuzzing found. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext_opt.h"
#include "json.h"
#include "log.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/blob.h"
#  include "ext/fuzz.h"
#  include "strategy.h"
#  include "ext/profile.h"

typedef struct {
    uint8_t *v[64];
    size_t n[64];
    size_t count;
} seeds;

static void add(void *ud, const uint8_t *d, size_t n)
{
    seeds *s = ud;
    if (s->count < 64) {
        s->v[s->count] = xmalloc(n ? n : 1);
        memcpy(s->v[s->count], d, n);
        s->n[s->count++] = n;
    }
}

static void seeds_free(seeds *s)
{
    for (size_t i = 0; i < s->count; i++)
        free(s->v[i]);
    s->count = 0;
}

TEST(fuzz_table)
{
    size_t n;
    const xfuzz_target *t = xfuzz_targets(&n);
    static const char *const want[] = {"pkt", "strategy", "apply", "pcap", "json", "l7",
                                       "tls", "quic", "inflate", "lists", "profile", "spec"};
    CHECK_INT((int)n, (int)ARRAY_LEN(want));
    for (size_t i = 0; i < n && i < ARRAY_LEN(want); i++) {
        CHECK_STR(t[i].name, want[i]);
        CHECK(xfuzz_find(want[i]) == &t[i]);
        CHECK(t[i].what && *t[i].what);
    }
    CHECK(xfuzz_find("nosuch") == NULL);
}

/* every target over its seeds and a few hundred mutations of them */
TEST(fuzz_targets_run)
{
    size_t n;
    const xfuzz_target *t = xfuzz_targets(&n);
    uint8_t buf[4096];
    for (size_t k = 0; k < n; k++) {
        seeds s;
        uint64_t rs = 42 + k;
        memset(&s, 0, sizeof(s));
        t[k].seeds(add, &s);
        CHECK(s.count > 0);
        for (size_t i = 0; i < s.count; i++)
            xfuzz_run(&t[k], s.v[i], s.n[i]);
        for (int i = 0; i < 300 && s.count; i++) {
            size_t b = (size_t)(xfuzz_rand(&rs) % s.count), l = s.n[b] < sizeof(buf) ? s.n[b] : sizeof(buf);
            memcpy(buf, s.v[b], l);
            l = xfuzz_mutate(buf, l, sizeof(buf), &rs, s.v[0], s.n[0]);
            CHECK(l <= sizeof(buf));
            xfuzz_run(&t[k], buf, l);
        }
        /* empty input and one byte */
        xfuzz_run(&t[k], buf, 0);
        buf[0] = 0xff;
        xfuzz_run(&t[k], buf, 1);
        seeds_free(&s);
    }
}

TEST(fuzz_mutate_bounds)
{
    uint8_t buf[64], other[100];
    uint64_t rs = 7;
    size_t n = 10;
    memset(buf, 'a', sizeof(buf));
    memset(other, 'b', sizeof(other));
    for (int i = 0; i < 20000; i++) {
        n = xfuzz_mutate(buf, n, sizeof(buf), &rs, other, sizeof(other));
        CHECK(n <= sizeof(buf));
        if (!n)
            n = 1;
    }
    /* full buffer: nothing is inserted past cap */
    n = sizeof(buf);
    for (int i = 0; i < 2000; i++) {
        size_t m = xfuzz_mutate(buf, n, n, &rs, other, sizeof(other));
        CHECK(m <= n);
    }
    /* the same state gives the same changes */
    {
        uint8_t a[32] = "the same input, the same output", b[32];
        uint64_t r1 = 99, r2 = 99;
        size_t la, lb;
        memcpy(b, a, sizeof(a));
        la = xfuzz_mutate(a, 31, sizeof(a), &r1, NULL, 0);
        lb = xfuzz_mutate(b, 31, sizeof(b), &r2, NULL, 0);
        CHECK_MEM(a, la, b, lb);
    }
}

/* the profile file from text: the keys with files are refused */
TEST(fuzz_profile_text)
{
    static const char *const refused[] = {"hostlist = x", "hostlist-exclude = x", "ipset = x", "ipset-exclude = x",
                                          "strategy-file = x", "hostlist-auto = x", "hostlist-auto-fail-threshold = 3"};
    const char *ok = "[profile a]\nfilter-tcp = 443\nhostlist-domains = example.com\nipset-ip = 10.0.0.0/8\n"
                     "hostlist-exclude-domains = b.example\nipset-exclude-ip = 10.1.0.0/16\n"
                     "strategy = [TCP:flags:PA]-xsplit{pos=1}-| \\/\n";
    xprofiles ps;
    sbuf e;
    sb_init(&e);
    CHECK_INT(xprof_build_text(ok, strlen(ok), &ps, &e), 0);
    CHECK_INT((int)ps.n, 1);
    CHECK(ps.n == 1 && ps.v[0]->st != NULL && ps.v[0]->ntcp == 1);
    xprof_free(&ps);
    for (size_t i = 0; i < ARRAY_LEN(refused); i++) {
        char *t = xasprintf("[profile a]\n%s\n", refused[i]);
        sb_reset(&e);
        CHECK_INT(xprof_build_text(t, strlen(t), &ps, &e), -1);
        CHECK(strstr(e.data, "no files here") != NULL);
        free(t);
    }
    sb_reset(&e);
    CHECK_INT(xprof_build_text("", 0, &ps, &e), -1); /* no profile */
    sb_free(&e);
}

/* found by fuzzing: a number out of int64 range (undefined in C) */
TEST(fuzz_json_int_range)
{
    const char *err = NULL;
    sbuf o;
    jw w;
    json_val *v = json_parse("{\"a\":1e30,\"b\":-1e30,\"c\":5.7,\"d\":-5.7,\"e\":9223372036854775807}", &err);
    CHECK(v != NULL);
    if (!v)
        return;
    CHECK(json_get_int(v, "a", 0) == INT64_MAX);
    CHECK(json_get_int(v, "b", 0) == INT64_MIN);
    CHECK(json_get_int(v, "c", 0) == 5);
    CHECK(json_get_int(v, "d", 0) == -5);
    CHECK(json_get_int(v, "e", 0) == INT64_MAX);
    CHECK(json_get_int(v, "x", 3) == 3);
    json_free(v);
    /* and the writer: a double past long long prints as a double */
    sb_init(&o);
    jw_init(&w, &o);
    jw_arr(&w);
    jw_dbl(&w, 6.17e40);
    jw_dbl(&w, -1e300);
    jw_dbl(&w, 42);
    jw_arr_end(&w);
    CHECK_STR(o.data, "[6.17e+40,-1e+300,42]");
    sb_free(&o);
}

/* found by fuzzing: an ICMP packet without a payload (xl7.c) */
TEST(fuzz_icmp_empty)
{
    static const uint8_t in[] = {0, 0, 0, 20, 0x45, 0, 0, 20, 0, 0, 0x40, 0, 64, 1, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2};
    xfuzz_run(xfuzz_find("apply"), in, sizeof(in));
    CHECK(1);
}

/* found by fuzzing: an empty "0x" blob leaked its buffer (ASan's leak
 * check in the sanitizer builds) */
TEST(fuzz_empty_hex_blob)
{
    sbuf e;
    strategy *s;
    sb_init(&e);
    s = strategy_parse("[TCP:flags:PA]-xfakedsplit{pos=method+2;pattern=0x}-| \\/", &e);
    CHECK(s == NULL);
    CHECK(strstr(e.data, "bad hex") != NULL);
    strategy_free(s);
    sb_reset(&e);
    CHECK_INT(blob_opt("empty:0x", &e), -1);
    sb_free(&e);
}

void suite_fuzz(void)
{
    log_level lv = log_get_level();
    ext_reset();
    xfuzz_init();
    RUN(fuzz_table);
    RUN(fuzz_targets_run);
    RUN(fuzz_mutate_bounds);
    RUN(fuzz_profile_text);
    RUN(fuzz_json_int_range);
    RUN(fuzz_icmp_empty);
    RUN(fuzz_empty_hex_blob);
    ext_reset();
    log_set_quiet(0);
    log_set_level(lv);
}

#else
/* found by fuzzing: an empty "0x" blob leaked its buffer (ASan's leak
 * check in the sanitizer builds) */
TEST(fuzz_empty_hex_blob)
{
    sbuf e;
    strategy *s;
    sb_init(&e);
    s = strategy_parse("[TCP:flags:PA]-xfakedsplit{pos=method+2;pattern=0x}-| \\/", &e);
    CHECK(s == NULL);
    CHECK(strstr(e.data, "bad hex") != NULL);
    strategy_free(s);
    sb_reset(&e);
    CHECK_INT(blob_opt("empty:0x", &e), -1);
    sb_free(&e);
}

void suite_fuzz(void) {}
#endif
