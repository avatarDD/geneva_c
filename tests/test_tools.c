/* geneva resolve and ip2net (X12a, src/ext/tools.c): the expected outputs
 * are zapret2's own ip2net and mdig over the same input. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/tools.h"

static void run(int v6, const char *plen, const char *v4t, const char *v6t, const char *in, const char *want)
{
    xip2net_cfg c;
    sbuf out, e;
    sb_init(&out);
    sb_init(&e);
    CHECK_INT(xip2net_init(&c, v6, plen, v4t, v6t, &e), 0);
    xip2net(&c, in, strlen(in), &out);
    CHECK_STR(out.data ? out.data : "", want);
    sb_free(&out);
    sb_free(&e);
}

TEST(ip2net_v4)
{
    const char *in = "10.0.0.1\n10.0.0.2\n10.0.0.3\n10.0.0.4\n10.0.0.5\n10.0.0.6\n10.0.0.1\n192.168.1.0/24\n"
                     "1.1.1.1-1.1.1.9\n8.8.8.8\n300.1.1.1\n1.2.3.4/32\n1.2.3.5/33\n";
    sbuf big;
    run(0, NULL, NULL, NULL, in, "192.168.1.0/24\n1.1.1.1-1.1.1.9\n1.2.3.4\n8.8.8.8\n10.0.0.0/29\n");
    run(0, "24-31", NULL, NULL, in, "192.168.1.0/24\n1.1.1.1-1.1.1.9\n1.2.3.4\n8.8.8.8\n10.0.0.0/29\n");
    sb_init(&big);
    for (int i = 0; i < 200; i++)
        sb_printf(&big, "10.1.%d.%d\n", i / 64, i % 64 * 4 + 1);
    run(0, "20-30", "1/8", NULL, big.data, "10.1.0.0/22\n");
    sb_free(&big);
    run(0, NULL, NULL, NULL, "", "");
}

TEST(ip2net_v6)
{
    const char *in = "2001:db8::1\n2001:db8::2\n2001:db8::3\n2001:db8::4\n2001:db8::5\n2001:db8:0:1::1\n"
                     "2a00::/32\n::1-::5\n::1/128\nzz::1\n";
    run(1, NULL, NULL, NULL, in, "2a00::/32\n::1-::5\n::1\n2001:db8::/63\n");
    run(1, "48-64", NULL, "2", in, "2a00::/32\n::1-::5\n::1\n2001:db8::/63\n");
}

TEST(ip2net_options)
{
    xip2net_cfg c;
    sbuf e;
    sb_init(&e);
    CHECK_INT(xip2net_init(&c, 0, NULL, NULL, NULL, &e), 0);
    CHECK_INT(c.zct_min, 2);
    CHECK_INT(c.zct_max, 10);
    CHECK_INT(xip2net_init(&c, 1, NULL, NULL, NULL, &e), 0);
    CHECK_INT(c.zct_min, 64);
    CHECK_INT(c.zct_max, 72);
    CHECK_INT(xip2net_init(&c, 0, "24", NULL, NULL, &e), 0);
    CHECK_INT(c.zct_min, 8);
    CHECK_INT(c.zct_max, 8);
    CHECK_INT(xip2net_init(&c, 0, "32", NULL, NULL, &e), -1);
    CHECK_INT(xip2net_init(&c, 0, "28-24", NULL, NULL, &e), -1);
    CHECK_INT(xip2net_init(&c, 0, "0", NULL, NULL, &e), -1);
    CHECK_INT(xip2net_init(&c, 1, "120-127", NULL, NULL, &e), 0);
    CHECK_INT(xip2net_init(&c, 0, NULL, "3/3", NULL, &e), -1);
    CHECK_INT(xip2net_init(&c, 0, NULL, "1/1", NULL, &e), -1);
    CHECK_INT(xip2net_init(&c, 0, NULL, "3", NULL, &e), -1);
    CHECK_INT(xip2net_init(&c, 1, NULL, NULL, "0", &e), -1);
    sb_free(&e);
}

TEST(dns_answer)
{
    static const uint8_t ans[] = {
        0, 1, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0,                                   /* header */
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,     /* question */
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34,               /* A */
        0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, /* AAAA */
        10, 11, 12, 13, 14, 15,                                                     /* */
        0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 0x0c,                     /* CNAME */
    };
    sbuf out;
    sb_init(&out);
    CHECK_INT(xdns_answer_ips(ans, sizeof(ans), &out), 0);
    CHECK_STR(out.data, "93.184.216.34\n1:203:405:607:809:a0b:c0d:e0f\n");
    sb_reset(&out);
    CHECK_INT(xdns_answer_ips(ans, 20, &out), -1);
    CHECK_INT(xdns_answer_ips(ans, 8, &out), -1);
    {
        uint8_t q[sizeof(ans)];
        memcpy(q, ans, sizeof(ans));
        q[2] = 1; /* a query, no answer */
        CHECK_INT(xdns_answer_ips(q, sizeof(q), &out), -1);
    }
    sb_free(&out);
}

void suite_tools(void);
void suite_tools(void)
{
    RUN(ip2net_v4);
    RUN(ip2net_v6);
    RUN(ip2net_options);
    RUN(dns_answer);
}

#else
void suite_tools(void);
void suite_tools(void) {}
#endif
