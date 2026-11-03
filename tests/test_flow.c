/* --first without conntrack (the flow table) and the WinDivert filter
 * options: --filter, --filter-file, --priority, the evaluator's slots. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "flowtab.h"
#include "fw.h"
#include "plat.h"
#include "test.h"
#include "util.h"

/* A packet as the flow table sees it: addresses, ports, protocol, flags. */
static gpkt mkpkt(int v6, int udp, const char *src, uint16_t sport, const char *dst, uint16_t dport,
                  uint16_t flags)
{
    gpkt p;
    memset(&p, 0, sizeof(p));
    p.ipver = v6 ? 6 : 4;
    inet_pton(v6 ? AF_INET6 : AF_INET, src, p.src);
    inet_pton(v6 ? AF_INET6 : AF_INET, dst, p.dst);
    p.l4 = udp ? LAYER_UDP : LAYER_TCP;
    p.sport = sport;
    p.dport = dport;
    p.tcpflags = flags;
    return p;
}

#define SYN 0x02
#define ACK 0x10
#define FIN 0x01
#define RST 0x04

static void test_flow_normalize(void)
{
    flowtab *t = flowtab_new(0);
    gpkt out = mkpkt(0, 0, "10.0.0.1", 40000, "1.2.3.4", 443, SYN);
    gpkt in = mkpkt(0, 0, "1.2.3.4", 443, "10.0.0.1", 40000, SYN | ACK);
    gpkt other = mkpkt(0, 0, "10.0.0.1", 40001, "1.2.3.4", 443, SYN);
    gpkt v6 = mkpkt(1, 0, "fd00::1", 40000, "fd00::2", 443, SYN);
    gpkt udp = mkpkt(0, 1, "10.0.0.1", 40000, "1.2.3.4", 443, 0);
    gpkt icmp = out;
    uint32_t o = 0, i = 0;
    int ev;
    t_current = "flow normalize";
    icmp.l4 = LAYER_NONE;

    CHECK_INT(flowtab_packet(t, &out, DIR_OUT, 3, 1000, &ev), 1);
    CHECK_INT(ev, 0);
    CHECK_INT(flowtab_packet(t, &in, DIR_IN, 3, 1001, &ev), 1);
    CHECK_INT(flowtab_count(t), 1); /* the reply is the same flow */
    CHECK_INT(flowtab_peek(t, &in, DIR_IN, 1002, &o, &i), 1);
    CHECK_INT(o, 1);
    CHECK_INT(i, 1);
    /* the same packet seen in the other direction is another flow */
    CHECK_INT(flowtab_peek(t, &out, DIR_IN, 1002, &o, &i), 0);
    flowtab_packet(t, &other, DIR_OUT, 3, 1002, &ev);
    flowtab_packet(t, &v6, DIR_OUT, 3, 1002, &ev);
    flowtab_packet(t, &udp, DIR_OUT, 3, 1002, &ev); /* same ports, other protocol */
    CHECK_INT(flowtab_count(t), 4);
    CHECK_INT(flowtab_packet(t, &icmp, DIR_OUT, 0, 1003, &ev), 1); /* no flow: always applies */
    CHECK_INT(flowtab_count(t), 4);
    flowtab_free(t);
}

static void test_flow_first(void)
{
    flowtab *t = flowtab_new(0);
    gpkt out = mkpkt(0, 0, "10.0.0.1", 40000, "1.2.3.4", 80, ACK);
    gpkt in = mkpkt(0, 0, "1.2.3.4", 80, "10.0.0.1", 40000, ACK);
    int ev, applied = 0;
    uint32_t o, i;
    t_current = "flow first";
    /* per direction: 3 out of 10 outbound, 3 out of 20 inbound */
    for (int k = 0; k < 10; k++)
        applied += flowtab_packet(t, &out, DIR_OUT, 3, 1000 + (uint64_t)k, &ev);
    CHECK_INT(applied, 3);
    applied = 0;
    for (int k = 0; k < 20; k++)
        applied += flowtab_packet(t, &in, DIR_IN, 3, 2000 + (uint64_t)k, &ev);
    CHECK_INT(applied, 3);
    CHECK_INT(flowtab_peek(t, &out, DIR_OUT, 3000, &o, &i), 1);
    CHECK_INT(o, 10);
    CHECK_INT(i, 20);
    /* the first packet of each direction comes first: out 1 applies, the
     * in packets before it count on their own */
    flowtab_free(t);
    t = flowtab_new(0);
    CHECK_INT(flowtab_packet(t, &in, DIR_IN, 1, 0, &ev), 1);
    CHECK_INT(flowtab_packet(t, &in, DIR_IN, 1, 1, &ev), 0);
    CHECK_INT(flowtab_packet(t, &out, DIR_OUT, 1, 2, &ev), 1);
    CHECK_INT(flowtab_packet(t, &out, DIR_OUT, 1, 3, &ev), 0);
    flowtab_free(t);
}

static void test_flow_lifetime(void)
{
    flowtab *t = flowtab_new(0);
    gpkt syn = mkpkt(0, 0, "10.0.0.1", 40000, "1.2.3.4", 80, SYN);
    gpkt fin_out = mkpkt(0, 0, "10.0.0.1", 40000, "1.2.3.4", 80, FIN | ACK);
    gpkt fin_in = mkpkt(0, 0, "1.2.3.4", 80, "10.0.0.1", 40000, FIN | ACK);
    gpkt rst_in = mkpkt(0, 0, "1.2.3.4", 80, "10.0.0.1", 40000, RST);
    gpkt udp = mkpkt(0, 1, "10.0.0.1", 5000, "8.8.8.8", 53, 0);
    uint32_t o, i;
    int ev;
    t_current = "flow lifetime";

    /* FIN one way keeps the flow for the idle time */
    flowtab_packet(t, &syn, DIR_OUT, 2, 0, &ev);
    flowtab_packet(t, &fin_out, DIR_OUT, 2, 1000, &ev);
    CHECK_INT(flowtab_expire(t, 1000 + FLOW_CLOSED_MS), 0);
    CHECK_INT(flowtab_count(t), 1);
    /* FIN both ways: gone 10 s later */
    flowtab_packet(t, &fin_in, DIR_IN, 2, 2000, &ev);
    CHECK_INT(flowtab_expire(t, 2000 + FLOW_CLOSED_MS - 1), 0);
    CHECK_INT(flowtab_expire(t, 2000 + FLOW_CLOSED_MS), 1);
    CHECK_INT(flowtab_count(t), 0);
    /* and the same 5-tuple then starts over */
    CHECK_INT(flowtab_packet(t, &syn, DIR_OUT, 1, 20000, &ev), 1);
    CHECK_INT(flowtab_peek(t, &syn, DIR_OUT, 20000, &o, &i), 1);
    CHECK_INT(o, 1);
    CHECK_INT(flowtab_packet(t, &syn, DIR_OUT, 1, 20001, &ev), 0);

    /* RST either way closes it */
    flowtab_packet(t, &rst_in, DIR_IN, 1, 21000, &ev);
    CHECK_INT(flowtab_peek(t, &syn, DIR_OUT, 21000 + FLOW_CLOSED_MS - 1, &o, &i), 1);
    CHECK_INT(flowtab_peek(t, &syn, DIR_OUT, 21000 + FLOW_CLOSED_MS, &o, &i), 0);
    /* an expired flow is new again even before a sweep */
    CHECK_INT(flowtab_packet(t, &syn, DIR_OUT, 1, 21000 + FLOW_CLOSED_MS, &ev), 1);
    CHECK_INT(flowtab_count(t), 1);

    /* idle: TCP 300 s, UDP 60 s */
    flowtab_packet(t, &udp, DIR_OUT, 1, 40000, &ev);
    CHECK_INT(flowtab_count(t), 2);
    CHECK_INT(flowtab_expire(t, 40000 + FLOW_UDP_IDLE_MS - 1), 0);
    CHECK_INT(flowtab_expire(t, 40000 + FLOW_UDP_IDLE_MS), 1);
    CHECK_INT(flowtab_peek(t, &udp, DIR_OUT, 40000 + FLOW_UDP_IDLE_MS, &o, &i), 0);
    CHECK_INT(flowtab_count(t), 1);
    CHECK_INT(flowtab_expire(t, 31000 + FLOW_TCP_IDLE_MS - 1), 0);
    CHECK_INT(flowtab_expire(t, 31000 + FLOW_TCP_IDLE_MS), 1);
    CHECK_INT(flowtab_count(t), 0);
    flowtab_free(t);
}

static void test_flow_lru(void)
{
    flowtab *t = flowtab_new(4);
    gpkt p[6];
    uint32_t o, i;
    int ev, evictions = 0;
    t_current = "flow lru";
    for (int k = 0; k < 6; k++)
        p[k] = mkpkt(0, 0, "10.0.0.1", (uint16_t)(40000 + k), "1.2.3.4", 443, ACK);
    for (int k = 0; k < 4; k++)
        flowtab_packet(t, &p[k], DIR_OUT, 5, (uint64_t)k, &ev);
    CHECK_INT(flowtab_count(t), 4);
    flowtab_packet(t, &p[0], DIR_OUT, 5, 10, &ev); /* 0 is active again: 1 is the oldest */
    flowtab_packet(t, &p[4], DIR_OUT, 5, 11, &ev);
    evictions += ev;
    CHECK_INT(ev, 1);
    CHECK_INT(flowtab_count(t), 4);
    CHECK_INT(flowtab_peek(t, &p[1], DIR_OUT, 12, &o, &i), 0);
    CHECK_INT(flowtab_peek(t, &p[0], DIR_OUT, 12, &o, &i), 1);
    CHECK_INT(o, 2);
    flowtab_packet(t, &p[5], DIR_OUT, 5, 13, &ev); /* pushes out 2 */
    evictions += ev;
    CHECK_INT(evictions, 2);
    CHECK_INT(flowtab_peek(t, &p[2], DIR_OUT, 14, &o, &i), 0);
    CHECK_INT(flowtab_peek(t, &p[3], DIR_OUT, 14, &o, &i), 1);
    /* an expired oldest flow makes room without counting as an eviction */
    flowtab_packet(t, &p[1], DIR_OUT, 5, 13 + FLOW_TCP_IDLE_MS + 1000, &ev);
    CHECK_INT(ev, 0);
    CHECK_INT(flowtab_count(t), 4);
    /* a full table at its real size takes 65536 flows and then evicts */
    flowtab_free(t);
    t = flowtab_new(0);
    evictions = 0;
    for (uint32_t k = 0; k < FLOW_MAX + 10; k++) {
        gpkt q = mkpkt(0, 1, "10.0.0.1", (uint16_t)(k & 0xffff), "1.2.3.4", (uint16_t)(1 + (k >> 16)), 0);
        flowtab_packet(t, &q, DIR_OUT, 1, 100, &ev);
        evictions += ev;
    }
    CHECK_INT(flowtab_count(t), FLOW_MAX);
    CHECK_INT(evictions, 10);
    flowtab_free(t);
}

/* ---- --filter, --filter-file, --priority ---------------------------------- */

static const optdef fdefs[] = {
    {"filter", 0, 1, "EXPR", ""},
    {"filter-file", 0, 1, "FILE", ""},
    {"priority", 0, 1, "N", ""},
    {NULL, 0, 0, NULL, NULL},
};

/* Parses argv (NULL-terminated) as on Windows (win = 1) or elsewhere. */
static int parse(int win, fw_config *c, char **owned, sbuf *err, const char *a0, const char *a1,
                 const char *a2, const char *a3)
{
    char *argv[5];
    int argc = 0, rc;
    args_t a;
    char aerr[128];
    const char *in[4] = {a0, a1, a2, a3};
    for (int i = 0; i < 4 && in[i]; i++)
        argv[argc++] = (char *)in[i];
    argv[argc] = NULL;
    fw_config_default(c);
    sb_reset(err);
    if (args_parse(&a, argc, argv, fdefs, aerr, sizeof(aerr)) < 0)
        return -2;
    rc = fw_parse_filter_args(&a, win, c, owned, err);
    args_free(&a);
    return rc;
}

static void test_filter_args(void)
{
    fw_config c;
    sbuf err, s;
    char *owned = NULL;
    char path[96];
    FILE *f;
    t_current = "filter args";
    sb_init(&err);
    sb_init(&s);

    /* not on Linux */
    CHECK_INT(parse(0, &c, &owned, &err, "--filter", "tcp", NULL, NULL), -1);
    CHECK(strstr(err.data, "Windows only: on Linux use --firewall none and your own rules") != NULL);
    CHECK_INT(parse(0, &c, &owned, &err, "--filter-file", "/nonexistent", NULL, NULL), -1);
    CHECK(strstr(err.data, "--filter-file is Windows only") != NULL);
    CHECK_INT(parse(0, &c, &owned, &err, "--priority", "5", NULL, NULL), -1);
    CHECK(strstr(err.data, "Windows only") != NULL);
    CHECK_INT(parse(0, &c, &owned, &err, NULL, NULL, NULL, NULL), 0);
    CHECK(c.filter == NULL);

    /* Windows */
    CHECK_INT(parse(1, &c, &owned, &err, "--filter", "ip.DstAddr == 1.2.3.4", NULL, NULL), 0);
    CHECK_STR(c.filter, "ip.DstAddr == 1.2.3.4");
    CHECK(owned == NULL && c.filter_file == NULL);
    CHECK_INT(c.priority, 0);
    CHECK_INT(parse(1, &c, &owned, &err, "--filter", "  ", NULL, NULL), -1);
    CHECK_INT(parse(1, &c, &owned, &err, "--filter", "tcp", "--filter-file", "x"), -1);
    CHECK(strstr(err.data, "exclude each other") != NULL);
    CHECK_INT(parse(1, &c, &owned, &err, "--priority", "-30000", NULL, NULL), 0);
    CHECK_INT(c.priority, -30000);
    CHECK_INT(parse(1, &c, &owned, &err, "--priority", "30000", NULL, NULL), 0);
    CHECK_INT(c.priority, 30000);
    CHECK_INT(parse(1, &c, &owned, &err, "--priority", "30001", NULL, NULL), -1);
    CHECK_INT(parse(1, &c, &owned, &err, "--priority", "x", NULL, NULL), -1);

    /* a file: lines joined by spaces, blank lines and CRLF ignored */
    snprintf(path, sizeof(path), "geneva-test-filter-%d.txt", plat_getpid());
    f = fopen(path, "wb");
    CHECK(f != NULL);
    if (f) {
        fputs("(outbound and ip.DstAddr == 1.2.3.4)\r\n\r\n  or (inbound and ip.SrcAddr == 1.2.3.4)  \n", f);
        fclose(f);
    }
    CHECK_INT(parse(1, &c, &owned, &err, "--filter-file", path, NULL, NULL), 0);
    CHECK_STR(c.filter, "(outbound and ip.DstAddr == 1.2.3.4) or (inbound and ip.SrcAddr == 1.2.3.4)");
    CHECK(owned != NULL && c.filter == owned);
    CHECK_STR(c.filter_file, path);
    free(owned);
    owned = NULL;
    /* empty, too long, missing */
    f = fopen(path, "wb");
    if (f) {
        fputs("\n  \n", f);
        fclose(f);
    }
    CHECK_INT(parse(1, &c, &owned, &err, "--filter-file", path, NULL, NULL), -1);
    CHECK(strstr(err.data, "no filter expression") != NULL);
    f = fopen(path, "wb");
    if (f) {
        for (int i = 0; i < FW_FILTER_FILE_MAX / 16 + 1; i++)
            fputs("tcp or udp or   ", f);
        fclose(f);
    }
    CHECK_INT(parse(1, &c, &owned, &err, "--filter-file", path, NULL, NULL), -1);
    CHECK(strstr(err.data, "65536") != NULL);
    remove(path);
    CHECK_INT(parse(1, &c, &owned, &err, "--filter-file", path, NULL, NULL), -1);
    CHECK(strstr(err.data, "cannot read") != NULL);
    CHECK(owned == NULL);
    sb_free(&err);
    sb_free(&s);
}

static void test_filter_expr(void)
{
    fw_config c;
    sbuf s, e;
    t_current = "filter expr";
    sb_init(&s);
    sb_init(&e);
    fw_config_default(&c);
    ports_parse("443", &c.ports);
    /* run: the expression replaces the built filter, loopback stays out */
    c.filter = "ip.DstAddr == 1.2.3.4 or ip.SrcAddr == 1.2.3.4";
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "(ip.DstAddr == 1.2.3.4 or ip.SrcAddr == 1.2.3.4) and not loopback");
    sb_reset(&s);
    CHECK_INT(fw_windivert_filter_expr(&c, "udp", &s, &e), 0);
    CHECK_STR(s.data, "(udp) and not loopback");
    sb_reset(&s);
    CHECK_INT(fw_windivert_filter_expr(&c, "", &s, &e), -1);
    /* evaluator: the slots' filter narrowed by the expression */
    sb_reset(&s);
    fw_config_default(&c);
    fw_eval_slots(&c, 30000, 128, 0);
    c.filter_narrow = 1;
    c.filter = "ip.DstAddr == 1.2.3.4";
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK_STR(s.data, "(!loopback and ((outbound and ((tcp.SrcPort >= 30000 and tcp.SrcPort <= 30127))) or "
                      "(inbound and ((tcp.DstPort >= 30000 and tcp.DstPort <= 30127))))) and "
                      "(ip.DstAddr == 1.2.3.4)");
    sb_reset(&s);
    c.filter = NULL;
    CHECK_INT(fw_windivert_filter(&c, &s, &e), 0);
    CHECK(s.data[0] == '!');
    /* the evaluator's ports for the rules (fw print --local-ports) */
    fw_config_default(&c);
    fw_eval_slots(&c, 31000, 64, 1);
    CHECK_INT(c.ports.n, 1);
    CHECK_INT(c.ports.lo[0], 31000);
    CHECK_INT(c.ports.hi[0], 31063);
    CHECK_INT(c.server_side, 1);
    CHECK_INT(c.udp, 1);
    sb_free(&s);
    sb_free(&e);
}

void suite_flow(void)
{
    test_flow_normalize();
    test_flow_first();
    test_flow_lifetime();
    test_flow_lru();
    test_filter_args();
    test_filter_expr();
}
