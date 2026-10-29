/* Packet parsing/building tests against scapy reference bytes. */
#include <stdlib.h>
#include <string.h>

#include "golden_pkt.h"
#include "pkt.h"
#include "test.h"

static gpkt *golden(const char *name, uint8_t *buf, size_t *len)
{
    for (size_t i = 0; i < sizeof(golden_pkts) / sizeof(golden_pkts[0]); i++) {
        if (strcmp(golden_pkts[i].name, name) == 0) {
            long n = hex_decode(golden_pkts[i].hex, buf, 2048);
            *len = (size_t)n;
            return pkt_parse(buf, (size_t)n);
        }
    }
    fprintf(stderr, "no golden %s\n", name);
    return NULL;
}

/* Applies one Geneva tamper-style set to "base" and compares to a golden. */
static void check_set(const char *golden_name, layer_id layer, const char *field, const char *text)
{
    uint8_t base[2048], exp[2048], out[4096];
    size_t blen, elen, olen;
    gval v;
    gpkt *p = golden("base", base, &blen);
    gpkt *e = golden(golden_name, exp, &elen);
    CHECK(p && e);
    if (!p || !e)
        return;
    CHECK_INT(field_parse(layer, field, text, &v), 0);
    CHECK_INT(pkt_set(p, layer, field, &v), 0);
    olen = pkt_build(p, out, sizeof(out));
    if (olen != elen || memcmp(out, exp, elen) != 0)
        fprintf(stderr, "  mismatch for %s\n", golden_name);
    CHECK_MEM(out, olen, exp, elen);
    gval_free(&v);
    pkt_free(p);
    pkt_free(e);
}

TEST(test_roundtrip)
{
    for (size_t i = 0; i < sizeof(golden_pkts) / sizeof(golden_pkts[0]); i++) {
        uint8_t in[2048], out[4096];
        size_t n = (size_t)hex_decode(golden_pkts[i].hex, in, sizeof(in)), olen;
        gpkt *p = pkt_parse(in, n);
        CHECK(p != NULL);
        if (!p)
            continue;
        /* untouched: byte-exact passthrough */
        olen = pkt_build(p, out, sizeof(out));
        CHECK_MEM(out, olen, in, n);
        /* rebuilt from fields with every value explicit: still identical */
        pkt_mark_dirty(p);
        olen = pkt_build(p, out, sizeof(out));
        if (olen != n || memcmp(out, in, n))
            fprintf(stderr, "  rebuild mismatch: %s\n", golden_pkts[i].name);
        CHECK_MEM(out, olen, in, n);
        /* and with every length/checksum recomputed (not for packets whose
         * stored values are deliberately wrong, or IP fragments, whose TCP
         * checksum covers the whole original segment) */
        p->auto_fields = 0xff;
        olen = pkt_build(p, out, sizeof(out));
        if (strcmp(golden_pkts[i].name, "dataofs10") && strcmp(golden_pkts[i].name, "chksum25776") &&
            strncmp(golden_pkts[i].name, "frag_", 5)) {
            if (olen != n || memcmp(out, in, n))
                fprintf(stderr, "  recompute mismatch: %s\n", golden_pkts[i].name);
            CHECK_MEM(out, olen, in, n);
        }
        pkt_free(p);
    }
}

TEST(test_get)
{
    uint8_t buf[2048];
    size_t n;
    gval v;
    gpkt *p = golden("base", buf, &n);
    CHECK(p != NULL);
    if (!p)
        return;
    CHECK(pkt_has_layer(p, LAYER_IP));
    CHECK(pkt_has_layer(p, LAYER_TCP));
    CHECK(!pkt_has_layer(p, LAYER_UDP));
    CHECK(!pkt_has_layer(p, LAYER_DNS));

    pkt_get(p, LAYER_TCP, "flags", &v);
    CHECK_STR(v.s, "PA");
    gval_free(&v);
    pkt_get(p, LAYER_IP, "flags", &v);
    CHECK_STR(v.s, "DF");
    gval_free(&v);
    pkt_get(p, LAYER_IP, "src", &v);
    CHECK_STR(v.s, "10.0.0.1");
    gval_free(&v);
    pkt_get(p, LAYER_IP, "ttl", &v);
    CHECK(!v.is_str && v.i == 64);
    pkt_get(p, LAYER_TCP, "options-mss", &v);
    CHECK(!v.is_str && v.i == 1460);
    pkt_get(p, LAYER_TCP, "options-wscale", &v);
    CHECK(!v.is_str && v.i == 7);
    pkt_get(p, LAYER_TCP, "options-nop", &v);
    CHECK_STR(v.s, "");
    gval_free(&v);
    pkt_get(p, LAYER_TCP, "options-timestamp", &v);
    CHECK_STR(v.s, "");
    gval_free(&v);
    pkt_get(p, LAYER_TCP, "load", &v);
    CHECK_STR(v.s, "GET%20/%20HTTP/1.1%0D%0AHost%3A%20example.com%0D%0A%0D%0A");
    gval_free(&v);
    pkt_get(p, LAYER_IP, "load", &v);
    CHECK_STR(v.s, "GET%20/%20HTTP/1.1%0D%0AHost%3A%20example.com%0D%0A%0D%0A");
    gval_free(&v);
    pkt_get(p, LAYER_TCP, "dataofs", &v);
    CHECK_INT(v.i, 7);
    CHECK_INT(pkt_get(p, LAYER_UDP, "sport", &v), -1);
    CHECK_INT(pkt_get(p, LAYER_TCP, "nosuch", &v), -1);
    pkt_free(p);
}

TEST(test_set_goldens)
{
    check_set("ttl10", LAYER_IP, "ttl", "10");
    check_set("flags_frapun", LAYER_TCP, "flags", "FRAPUN");
    check_set("dataofs10", LAYER_TCP, "dataofs", "10");
    check_set("chksum25776", LAYER_TCP, "chksum", "25776");
    check_set("ipflags_mfdf", LAYER_IP, "flags", "MF+DF");
    check_set("opt_wscale200", LAYER_TCP, "options-wscale", "200");
    check_set("opt_ts", LAYER_TCP, "options-timestamp", "12345");
    check_set("opt_mss0", LAYER_TCP, "options-mss", "");
    check_set("opt_uto", LAYER_TCP, "options-uto", "300");
    check_set("opt_md5", LAYER_TCP, "options-md5header", "00112233445566778899aabbccddeeff");
    check_set("opt_sackok", LAYER_TCP, "options-sackok", "");
    check_set("opt_nop_existing", LAYER_TCP, "options-nop", "");
    check_set("opt_altchksum", LAYER_TCP, "options-altchksum", "7");
    check_set("load_hello", LAYER_TCP, "load", "hello%20world");
    check_set("ipload_xyz", LAYER_IP, "load", "xyz");
}

TEST(test_dns)
{
    uint8_t buf[2048], exp[2048], out[4096];
    size_t n, en, on;
    gval v;
    gpkt *p = golden("dns", buf, &n);
    gpkt *e;
    CHECK(p != NULL);
    if (!p)
        return;
    CHECK(pkt_has_layer(p, LAYER_DNS));
    CHECK(pkt_has_layer(p, LAYER_DNSQR));
    pkt_get(p, LAYER_DNSQR, "qname", &v);
    CHECK_STR(v.s, "www.example.com.");
    gval_free(&v);
    pkt_get(p, LAYER_DNS, "rd", &v);
    CHECK_INT(v.i, 1);
    pkt_get(p, LAYER_DNS, "qdcount", &v);
    CHECK_INT(v.i, 1);
    pkt_get(p, LAYER_DNSQR, "qtype", &v);
    CHECK_INT(v.i, 1);
    pkt_get(p, LAYER_UDP, "load", &v); /* parsed as DNS: no raw load */
    CHECK_STR(v.s, "");
    gval_free(&v);

    gval_int(&v, 0x4321);
    CHECK_INT(pkt_set(p, LAYER_DNS, "id", &v), 0);
    e = golden("dns_id", exp, &en);
    on = pkt_build(p, out, sizeof(out));
    CHECK_MEM(out, on, exp, en);
    pkt_free(p);
    pkt_free(e);

    p = golden("dns", buf, &n);
    e = golden("dns_compressed", exp, &en);
    CHECK_INT(pkt_dns_compress(p), 1);
    on = pkt_build(p, out, sizeof(out));
    CHECK_MEM(out, on, exp, en);
    pkt_free(p);
    pkt_free(e);

    p = golden("dns", buf, &n);
    gval_str(&v, "blocked.example.org");
    CHECK_INT(pkt_set(p, LAYER_DNSQR, "qname", &v), 0);
    gval_free(&v);
    pkt_get(p, LAYER_DNSQR, "qname", &v);
    CHECK_STR(v.s, "blocked.example.org.");
    gval_free(&v);
    pkt_get(p, LAYER_DNSQR, "qtype", &v);
    CHECK_INT(v.i, 1);
    pkt_free(p);
}

TEST(test_ipv6)
{
    uint8_t buf[2048], exp[2048], out[4096];
    size_t n, en, on;
    gval v;
    gpkt *p = golden("v6syn", buf, &n);
    gpkt *e = golden("v6_hlim3", exp, &en);
    CHECK(p && e);
    if (!p || !e)
        return;
    CHECK(pkt_has_layer(p, LAYER_IPV6));
    CHECK(pkt_has_layer(p, LAYER_IP)); /* IPv4 names alias onto IPv6 */
    pkt_get(p, LAYER_IP, "ttl", &v);
    CHECK_INT(v.i, 64);
    CHECK_INT(pkt_get(p, LAYER_IP, "chksum", &v), -1);
    gval_int(&v, 3);
    CHECK_INT(pkt_set(p, LAYER_IP, "ttl", &v), 0);
    on = pkt_build(p, out, sizeof(out));
    CHECK_MEM(out, on, exp, en);
    pkt_get(p, LAYER_IPV6, "src", &v);
    CHECK_STR(v.s, "2001:db8::1");
    gval_free(&v);
    pkt_free(p);
    pkt_free(e);
}

TEST(test_flags_parsing)
{
    uint16_t f;
    uint8_t ipf;
    char s[32];
    CHECK_INT(tcp_flags_parse("SA", &f), 0);
    CHECK_INT(f, 0x12);
    tcp_flags_str(f, s);
    CHECK_STR(s, "SA");
    CHECK_INT(tcp_flags_parse("AP", &f), 0);
    tcp_flags_str(f, s);
    CHECK_STR(s, "PA");
    CHECK_INT(tcp_flags_parse("X", &f), -1);
    CHECK_INT(tcp_flags_parse("", &f), 0);
    CHECK_INT(f, 0);
    CHECK_INT(ip_flags_parse("DF+MF", &ipf), 0);
    ip_flags_str(ipf, s);
    CHECK_STR(s, "MF+DF");
    CHECK_INT(ip_flags_parse("XF", &ipf), -1);
}

TEST(test_field_parse)
{
    gval v;
    CHECK_INT(field_parse(LAYER_TCP, "flags", "SA", &v), 0);
    CHECK(v.is_str);
    gval_free(&v);
    CHECK_INT(field_parse(LAYER_TCP, "flags", "SQ", &v), -1);
    CHECK_INT(field_parse(LAYER_IP, "ttl", "abc", &v), -1);
    CHECK_INT(field_parse(LAYER_IP, "ttl", "10", &v), 0);
    CHECK(!v.is_str && v.i == 10);
    CHECK_INT(field_parse(LAYER_TCP, "load", "123", &v), 0);
    CHECK(v.is_str);
    gval_free(&v);
    CHECK_INT(field_parse(LAYER_TCP, "options-md5header", "zz", &v), -1);
    CHECK_INT(field_parse(LAYER_TCP, "nonsense", "1", &v), -1);
}

TEST(test_gen_and_restrict)
{
    sbuf msg;
    const char *names[32];
    for (int l = 0; l < LAYER_COUNT; l++) {
        const char *const *f = layer_fields((layer_id)l);
        for (; *f; f++) {
            gval v;
            int rc = field_gen((layer_id)l, *f, &v);
            if (!(l == LAYER_DNS && !strcmp(*f, "qd")))
                CHECK_INT(rc, 0);
            gval_free(&v);
        }
    }
    sb_init(&msg);
    CHECK_INT(fields_restrict("TCP", "", "", &msg), 0);
    CHECK(layer_is_allowed(LAYER_TCP));
    CHECK(!layer_is_allowed(LAYER_IP));
    CHECK_INT(fields_restrict("TCP,IP", "flags,ttl", "", &msg), 0);
    CHECK_INT(layer_allowed_fields(LAYER_TCP, names, 32), 1);
    CHECK_STR(names[0], "flags");
    CHECK_INT(layer_allowed_fields(LAYER_IP, names, 32), 2);
    CHECK_INT(fields_restrict("UDP", "flags", "", &msg), -1);
    CHECK_INT(fields_restrict("TCP", "", "load,chksum", &msg), 0);
    CHECK(!field_is_allowed(LAYER_TCP, "load"));
    CHECK(field_is_allowed(LAYER_TCP, "seq"));
    fields_reset_restrictions();
    sb_free(&msg);
}

TEST(test_bad_packets)
{
    uint8_t junk[64] = {0x45, 0, 0, 10};
    CHECK(pkt_parse(junk, 10) == NULL);       /* shorter than an IPv4 header */
    junk[0] = 0x4f;                           /* ihl=15 > length */
    CHECK(pkt_parse(junk, 40) == NULL);
    junk[0] = 0x75;
    CHECK(pkt_parse(junk, 40) == NULL);       /* version 7 */
    {
        /* TCP with a broken data offset falls back to a raw IP payload */
        uint8_t p[40] = {0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6};
        gpkt *g;
        p[20 + 12] = 0xf0;
        g = pkt_parse(p, 40);
        CHECK(g != NULL);
        if (g) {
            CHECK(!pkt_has_layer(g, LAYER_TCP));
            pkt_free(g);
        }
    }
}

void suite_pkt(void)
{
    RUN(test_roundtrip);
    RUN(test_get);
    RUN(test_set_goldens);
    RUN(test_dns);
    RUN(test_ipv6);
    RUN(test_flags_parsing);
    RUN(test_field_parse);
    RUN(test_gen_and_restrict);
    RUN(test_bad_packets);
}
