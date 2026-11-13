/* nl80211 messages of --filter-ssid (src/ext/wlan.c) */
#include <string.h>

#include "test.h"

#if GENEVA_EXT
#  include "args.h"
#  include "ext/winnet.h"
#  include "ext/wlan.h"

/* a datagram being built: messages of attributes */
typedef struct {
    uint8_t b[2048];
    size_t n, msg, nest;
} dg;

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static void msg(dg *d, uint16_t type, uint32_t seq)
{
    d->msg = d->n;
    memset(d->b + d->n, 0, 20);
    put16(d->b + d->n + 4, type);
    put32(d->b + d->n + 8, seq);
    d->n += 20; /* nlmsghdr and genlmsghdr */
}

static void end(dg *d) { put32(d->b + d->msg, (uint32_t)(d->n - d->msg)); }

static void attr(dg *d, uint16_t type, const void *v, size_t len)
{
    put16(d->b + d->n, (uint16_t)(4 + len));
    put16(d->b + d->n + 2, type);
    memcpy(d->b + d->n + 4, v, len);
    d->n += 4 + len;
    while (d->n % 4)
        d->b[d->n++] = 0;
}

static void attr32(dg *d, uint16_t type, uint32_t v) { attr(d, type, &v, 4); }

static void nest_open(dg *d, uint16_t type)
{
    d->nest = d->n;
    put16(d->b + d->n + 2, (uint16_t)(type | 0x8000));
    d->n += 4;
}

static void nest_close(dg *d) { put16(d->b + d->nest, (uint16_t)(d->n - d->nest)); }

/* NLMSG_DONE, NLMSG_ERROR */
static void done(dg *d, uint16_t type, uint32_t seq, int32_t code)
{
    memset(d->b + d->n, 0, 20);
    put32(d->b + d->n, 20);
    put16(d->b + d->n + 4, type);
    put32(d->b + d->n + 8, seq);
    memcpy(d->b + d->n + 16, &code, 4);
    d->n += 20;
}

TEST(wlan_build)
{
    uint8_t b[64];
    uint32_t idx = 7;
    size_t n = xwlan_build(b, sizeof(b), 0x10, 1, 5, 3, 2, "nl80211", 8);
    CHECK_INT((int)n, 16 + 4 + 4 + 8);
    CHECK_INT(b[16], 3); /* CTRL_CMD_GETFAMILY */
    CHECK_INT(b[17], 1);
    CHECK(!memcmp(b + 24, "nl80211", 8));
    n = xwlan_build(b, sizeof(b), 28, 0x301, 6, 32, 3, &idx, 4);
    CHECK_INT((int)n, 28);
    CHECK_INT(b[16], 32); /* NL80211_CMD_GET_SCAN */
    CHECK_INT((int)xwlan_build(b, 20, 28, 1, 1, 5, 3, &idx, 4), 0);
}

TEST(wlan_parse)
{
    dg d;
    uint16_t id = 0;
    int err = 0;
    xwlan_set s;
    /* the family: CTRL_ATTR_FAMILY_NAME, CTRL_ATTR_FAMILY_ID */
    memset(&d, 0, sizeof(d));
    msg(&d, 0x10, 9);
    attr(&d, 2, "nl80211", 8);
    {
        uint16_t v = 28;
        attr(&d, 1, &v, 2);
    }
    end(&d);
    CHECK_INT(xwlan_parse_family(d.b, d.n, 9, &id, &err), 1);
    CHECK_INT(id, 28);
    CHECK_INT(xwlan_parse_family(d.b, d.n, 8, &id, &err), 0); /* another request's */
    memset(&d, 0, sizeof(d));
    done(&d, 2, 9, -2); /* ENOENT: no nl80211 */
    CHECK_INT(xwlan_parse_family(d.b, d.n, 9, &id, &err), -1);
    CHECK_INT(err, 2);

    /* GET_INTERFACE: two interfaces, one with an SSID (before Linux 5.19) */
    memset(&d, 0, sizeof(d));
    memset(&s, 0, sizeof(s));
    msg(&d, 28, 10);
    attr32(&d, 3, 4);
    attr(&d, 4, "wlan0", 6);
    end(&d);
    msg(&d, 28, 10);
    attr32(&d, 3, 5);
    attr(&d, 4, "wlan1", 6);
    attr(&d, 52, "old-kernel", 10);
    end(&d);
    CHECK_INT(xwlan_parse_ifaces(d.b, d.n, 10, &s, &err), 0);
    memset(&d, 0, sizeof(d));
    msg(&d, 28, 10); /* the same interface again: once */
    attr32(&d, 3, 4);
    attr(&d, 4, "wlan0", 6);
    end(&d);
    done(&d, 3, 10, 0);
    CHECK_INT(xwlan_parse_ifaces(d.b, d.n, 10, &s, &err), 1);
    CHECK_INT(s.n, 2);
    CHECK_STR(s.v[0].ifname, "wlan0");
    CHECK_INT((int)s.v[0].ifindex, 4);
    CHECK_STR(s.v[0].ssid, "");
    CHECK_STR(s.v[1].ssid, "old-kernel");

    /* GET_SCAN of wlan0: a BSS seen, then the associated one */
    memset(&d, 0, sizeof(d));
    msg(&d, 28, 11);
    attr32(&d, 3, 4);
    nest_open(&d, 47);
    {
        static const uint8_t ie[] = {0, 5, 'o', 't', 'h', 'e', 'r', 1, 1, 0x82};
        attr(&d, 6, ie, sizeof(ie));
    }
    nest_close(&d);
    end(&d);
    msg(&d, 28, 11);
    attr32(&d, 3, 4);
    nest_open(&d, 47);
    {
        static const uint8_t ie[] = {1, 1, 0x82, 0, 4, 'h', 'o', 'm', 'e'};
        attr(&d, 6, ie, sizeof(ie));
        attr32(&d, 9, 1); /* NL80211_BSS_STATUS_ASSOCIATED */
    }
    nest_close(&d);
    end(&d);
    done(&d, 3, 11, 0);
    CHECK_INT(xwlan_parse_scan(d.b, d.n, 11, &s, &err), 1);
    CHECK_STR(s.v[0].ssid, "home");
    CHECK_STR(s.v[1].ssid, "old-kernel");

    /* truncated elements and a malformed message */
    memset(&d, 0, sizeof(d));
    msg(&d, 28, 12);
    attr32(&d, 3, 5);
    nest_open(&d, 47);
    {
        static const uint8_t ie[] = {0, 40, 'x'};
        attr(&d, 6, ie, sizeof(ie));
        attr32(&d, 9, 1);
    }
    nest_close(&d);
    end(&d);
    CHECK_INT(xwlan_parse_scan(d.b, d.n, 12, &s, &err), 0);
    CHECK_STR(s.v[1].ssid, "old-kernel");
    put32(d.b, 9999);
    CHECK_INT(xwlan_parse_scan(d.b, d.n, 12, &s, &err), -1);

    /* no socket: nothing is connected */
    CHECK_INT(xwlan_on(), 0);
    {
        char ss[33];
        CHECK_INT(xwlan_ssid("wlan0", ss), 0);
    }
}

/* --ssid-filter, --nlm-filter: names, GUIDs (zapret2's str2guid) */
TEST(winnet_helpers)
{
    uint8_t g[16];
    char s[37], **v = NULL;
    size_t n = 0;
    CHECK_INT(xwinnet_guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B", g), 0);
    CHECK_INT(g[0], 0x01);
    CHECK_INT(g[3], 0xDC);
    CHECK_INT(g[4], 0x0F);
    CHECK_INT(g[6], 0x9B);
    CHECK_INT(g[8], 0x8D);
    CHECK_INT(g[15], 0x3B);
    xwinnet_guid_str(g, s);
    CHECK_STR(s, "DCB00C01-570F-4A9B-8D69-199FDBA5723B");
    CHECK_INT(xwinnet_guid("dcb00c01-570f-4a9b-8d69-199fdba5723b", g), 0);
    CHECK_INT(xwinnet_guid("{DCB00C01-570F-4A9B-8D69-199FDBA5723B}", g), -1);
    CHECK_INT(xwinnet_guid("DCB00C01-570F-4A9B-8D69+199FDBA5723B", g), -1);
    CHECK_INT(xwinnet_guid("DCB00C01-570F-4A9B-8D69-199FDBA5723G", g), -1);
    CHECK_INT(xwinnet_list_parse("home,DCB00C01-570F-4A9B-8D69-199FDBA5723B", 127, &v, &n), 0);
    CHECK_INT((int)n, 2);
    CHECK_INT(xwinnet_list_has(v, n, "home", NULL), 1);
    CHECK_INT(xwinnet_list_has(v, n, "Home", NULL), 0);
    CHECK_INT(xwinnet_guid("DCB00C01-570F-4A9B-8D69-199FDBA5723B", g), 0);
    CHECK_INT(xwinnet_list_has(v, n, "other", g), 1);
    g[15] ^= 1;
    CHECK_INT(xwinnet_list_has(v, n, "other", g), 0);
    CHECK_INT(xwinnet_list_parse("x,", 127, &v, &n), -1);
    xwinnet_list_free(v, n);
    CHECK_INT(xwinnet_ok(), 1); /* no filters */
#  ifndef _WIN32
    {
        static const optdef defs[] = {{"ssid-filter", 0, 1, "S", ""}, {"ssid-filter-neg", 0, 2, "0|1", ""},
                                       {"nlm-filter", 0, 1, "N", ""}, {"nlm-filter-neg", 0, 2, "0|1", ""},
                                       {NULL, 0, 0, NULL, NULL}};
        const char *av[] = {"--ssid-filter", "home", NULL}, *bv[] = {"--nlm-filter-neg=2", NULL};
        args_t a;
        char err[128];
        sbuf e;
        sb_init(&e);
        CHECK_INT(args_parse(&a, 2, (char **)av, defs, err, sizeof(err)), 0);
        CHECK_INT(xwinnet_start(&a, &e), -1);
        CHECK_STR(e.data, "--ssid-filter and --nlm-filter are Windows-only (Linux: --filter-ssid of a profile)");
        args_free(&a);
        sb_reset(&e);
        CHECK_INT(args_parse(&a, 1, (char **)bv, defs, err, sizeof(err)), 0);
        CHECK_INT(xwinnet_start(&a, &e), -1);
        CHECK_STR(e.data, "bad --nlm-filter-neg 2 (0 or 1)");
        args_free(&a);
        sb_free(&e);
        CHECK_INT(xwinnet_ok(), 1);
    }
#  endif
}

void suite_wlan(void)
{
    RUN(wlan_build);
    RUN(wlan_parse);
    RUN(winnet_helpers);
}

#else
void suite_wlan(void) {}
#endif
