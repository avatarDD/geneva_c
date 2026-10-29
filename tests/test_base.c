/* Tests for util, json, args and rng. */
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "json.h"
#include "rng.h"
#include "test.h"
#include "util.h"

TEST(test_sbuf)
{
    sbuf b;
    sb_init(&b);
    sb_puts(&b, "abc");
    sb_printf(&b, "-%d-", 42);
    sb_putc(&b, 'x');
    CHECK_STR(b.data, "abc-42-x");
    CHECK_INT(b.len, 8);
    for (int i = 0; i < 1000; i++)
        sb_putc(&b, 'y');
    CHECK_INT(b.len, 1008);
    sb_free(&b);
}

TEST(test_url_quote)
{
    sbuf b;
    uint8_t out[64];
    const char *raw = "GET / HTTP/1.1\r\nHost: a~b_c.d-e\r\n";
    sb_init(&b);
    url_quote(&b, (const uint8_t *)raw, strlen(raw));
    /* identical to Python's urllib.parse.quote() */
    CHECK_STR(b.data, "GET%20/%20HTTP/1.1%0D%0AHost%3A%20a~b_c.d-e%0D%0A");
    CHECK_INT(url_unquote(b.data, out), strlen(raw));
    CHECK_MEM(out, strlen(raw), raw, strlen(raw));
    sb_free(&b);
}

TEST(test_hex)
{
    uint8_t buf[8];
    sbuf b;
    CHECK_INT(hex_decode("00ff10", buf, sizeof(buf)), 3);
    CHECK_INT(buf[1], 0xff);
    CHECK_INT(hex_decode("0g", buf, sizeof(buf)), -1);
    CHECK_INT(hex_decode("abc", buf, sizeof(buf)), -1);
    sb_init(&b);
    hex_encode(&b, buf, 3);
    CHECK_STR(b.data, "00ff10");
    sb_free(&b);
}

TEST(test_parse_numbers)
{
    int64_t v;
    uint64_t u;
    CHECK_INT(parse_i64("-17", &v), 0);
    CHECK_INT(v, -17);
    CHECK_INT(parse_i64("12a", &v), -1);
    CHECK_INT(parse_i64("", &v), -1);
    CHECK_INT(parse_u64("0x40000000", &u), 0);
    CHECK_INT(u, 0x40000000);
    CHECK_INT(parse_u64("-1", &u), -1);
}

TEST(test_json_writer)
{
    sbuf sb;
    jw w;
    sb_init(&sb);
    jw_init(&w, &sb);
    jw_obj(&w);
    jw_kstr(&w, "s", "a\"b\\c\n\x01");
    jw_kint(&w, "i", -5);
    jw_key(&w, "arr");
    jw_arr(&w);
    jw_int(&w, 1);
    jw_bool(&w, 1);
    jw_null(&w);
    jw_obj(&w);
    jw_obj_end(&w);
    jw_arr_end(&w);
    jw_kdbl(&w, "d", 1.5);
    jw_obj_end(&w);
    CHECK_STR(sb.data, "{\"s\":\"a\\\"b\\\\c\\n\\u0001\",\"i\":-5,\"arr\":[1,true,null,{}],\"d\":1.5}");
    sb_free(&sb);
}

TEST(test_json_parser)
{
    const char *err = NULL;
    json_val *v = json_parse(" {\"cmd\":\"set_strategy\",\"id\":7,\"x\":[1,2,{\"y\":null}],"
                             "\"u\":\"\\u00e9\\ud83d\\ude00\",\"t\":true} ",
                             &err);
    CHECK(v != NULL);
    if (!v)
        return;
    CHECK_STR(json_get_str(v, "cmd", NULL), "set_strategy");
    CHECK_INT(json_get_int(v, "id", 0), 7);
    CHECK_INT(json_get_bool(v, "t", 0), 1);
    CHECK_STR(json_get_str(v, "u", NULL), "\xc3\xa9\xf0\x9f\x98\x80");
    CHECK_INT(json_get(v, "x")->n, 3);
    CHECK(json_get(v, "missing") == NULL);
    json_free(v);

    CHECK(json_parse("{\"a\":1,}", &err) == NULL);
    CHECK(json_parse("[1 2]", &err) == NULL);
    CHECK(json_parse("{\"a\":1} x", &err) == NULL);
    CHECK(json_parse("\"abc", &err) == NULL);
}

TEST(test_args)
{
    static const optdef defs[] = {
        {"port", 'p', 1, "PORT", ""},
        {"flag", 0, 0, NULL, ""},
        {"target", 0, 1, "T", ""},
        {"frag", 0, 1, "N", ""},
        {NULL, 0, 0, NULL, NULL},
    };
    char *argv[] = {"--port=80", "--flag", "pos1", "--target", "a", "--target=b", "-p", "443",
                    "--frag", "-1", "--", "--notopt"};
    args_t a;
    char err[128];
    int64_t v;
    int idx = 0;
    CHECK_INT(args_parse(&a, (int)ARRAY_LEN(argv), argv, defs, err, sizeof(err)), 0);
    CHECK_STR(arg_str(&a, "port", NULL), "443");
    CHECK(arg_has(&a, "flag"));
    CHECK_STR(arg_next(&a, "target", &idx), "a");
    CHECK_STR(arg_next(&a, "target", &idx), "b");
    CHECK(arg_next(&a, "target", &idx) == NULL);
    CHECK_INT(a.npos, 2);
    CHECK_STR(a.pos[1], "--notopt");
    CHECK_INT(arg_int(&a, "frag", 0, -1, 100, &v), 0);
    CHECK_INT(v, -1);
    args_free(&a);

    {
        char *bad[] = {"--nope"};
        CHECK_INT(args_parse(&a, 1, bad, defs, err, sizeof(err)), -1);
        args_free(&a);
    }
}

TEST(test_rng)
{
    int seen[10] = {0};
    rng_global_seed(99);
    uint64_t a = rng_u64();
    rng_global_seed(99);
    CHECK(rng_u64() == a);
    for (int i = 0; i < 2000; i++) {
        int64_t r = rng_range(0, 9);
        CHECK(r >= 0 && r <= 9);
        if (r >= 0 && r <= 9)
            seen[r]++;
        double d = rng_real();
        CHECK(d >= 0.0 && d < 1.0);
    }
    for (int i = 0; i < 10; i++)
        CHECK(seen[i] > 100);
}

void suite_base(void)
{
    RUN(test_sbuf);
    RUN(test_url_quote);
    RUN(test_hex);
    RUN(test_parse_numbers);
    RUN(test_json_writer);
    RUN(test_json_parser);
    RUN(test_args);
    RUN(test_rng);
}
