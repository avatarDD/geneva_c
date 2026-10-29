/* Probes against servers in this process, and the evaluator's arithmetic. */
#include <stdlib.h>
#include <string.h>

#include "evaluator.h"
#include "plat.h"
#include "probe.h"
#include "strategy.h"
#include "test.h"

/* ---- a TCP server with canned answers ------------------------------------ */

enum {
    M_HTTP_CL, M_HTTP_CHUNKED, M_HTTP_EOF, M_HTTP_PARTIAL, M_HTTP_BLOCK, M_RESET, M_SILENT,
    M_TLS13, M_TLS12, M_TLS_SPLIT, M_ECHO, M_DNS_TCP,
};

static struct {
    sock_t ls;
    uint16_t port;
    volatile int mode, stop;
    volatile int peer_port;
    plat_thread_t th;
} srv;

static void send_bytes(sock_t c, const void *p, size_t n) { send(c, (const char *)p, (int)n, 0); }

/* Waits for the client to close (or 2 s). */
static void drain(sock_t c)
{
    char buf[512];
    plat_pollfd p;
    for (int i = 0; i < 40; i++) {
        p.fd = c;
        p.events = POLLIN;
        p.revents = 0;
        if (plat_poll(&p, 1, 50) > 0 && recv(c, buf, sizeof(buf), 0) <= 0)
            return;
    }
}

static size_t read_request(sock_t c, uint8_t *buf, size_t cap)
{
    size_t n = 0;
    plat_pollfd p;
    for (int i = 0; i < 20 && n < cap; i++) {
        int k;
        p.fd = c;
        p.events = POLLIN;
        p.revents = 0;
        if (plat_poll(&p, 1, 50) <= 0) {
            if (n)
                break;
            continue;
        }
        k = (int)recv(c, (char *)buf + n, (int)(cap - n), 0);
        if (k <= 0)
            break;
        n += (size_t)k;
        if (n >= 4 && !memcmp(buf + n - 4, "\r\n\r\n", 4))
            break;
    }
    return n;
}

static void put_sh(uint8_t *p)
{
    /* a ServerHello message: type 2, length 38 (contents do not matter here) */
    p[0] = 2;
    p[1] = 0;
    p[2] = 0;
    p[3] = 38;
    memset(p + 4, 0x42, 38);
}

static void serve_one(sock_t c)
{
    uint8_t req[2048];
    size_t n = read_request(c, req, sizeof(req));
    switch (srv.mode) {
    case M_HTTP_CL: {
        static const char r[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        send_bytes(c, r, sizeof(r) - 1);
        drain(c); /* keeps the connection open: the probe must stop on its own */
        break;
    }
    case M_HTTP_CHUNKED: {
        static const char r[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        send_bytes(c, r, sizeof(r) - 1);
        drain(c);
        break;
    }
    case M_HTTP_EOF: {
        static const char r[] = "HTTP/1.0 200 OK\r\nServer: t\r\n\r\nhello body";
        send_bytes(c, r, sizeof(r) - 1);
        break;
    }
    case M_HTTP_PARTIAL: {
        static const char r[] = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello";
        send_bytes(c, r, sizeof(r) - 1);
        break;
    }
    case M_HTTP_BLOCK: {
        static const char r[] = "HTTP/1.1 403 Forbidden\r\nContent-Length: 14\r\n\r\nblocked by isp";
        send_bytes(c, r, sizeof(r) - 1);
        drain(c);
        break;
    }
    case M_RESET: {
        struct linger l = {1, 0};
        setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof(l));
        break;
    }
    case M_SILENT:
        drain(c);
        break;
    case M_TLS13: {
        uint8_t r[5 + 42 + 6 + 5 + 16];
        size_t k = 0;
        if (n < 5 || req[0] != 0x16 || req[5] != 1)
            break;
        memcpy(r, "\x16\x03\x03\x00\x2a", 5);
        put_sh(r + 5);
        k = 47;
        memcpy(r + k, "\x14\x03\x03\x00\x01\x01", 6);
        k += 6;
        memcpy(r + k, "\x17\x03\x03\x00\x10", 5);
        k += 5;
        memset(r + k, 0x99, 16);
        k += 16;
        send_bytes(c, r, k);
        drain(c);
        break;
    }
    case M_TLS12: {
        uint8_t r[5 + 42 + 14 + 4];
        memcpy(r, "\x16\x03\x03\x00\x3c", 5);
        put_sh(r + 5);
        memcpy(r + 47, "\x0b\x00\x00\x0a", 4); /* Certificate, 10 bytes */
        memset(r + 51, 0x30, 10);
        memcpy(r + 61, "\x0e\x00\x00\x00", 4); /* ServerHelloDone */
        send_bytes(c, r, sizeof(r));
        drain(c);
        break;
    }
    case M_TLS_SPLIT: {
        /* ServerHello split over two records, sent in pieces */
        uint8_t sh[42], r[64];
        put_sh(sh);
        memcpy(r, "\x16\x03\x03\x00\x0a", 5);
        memcpy(r + 5, sh, 10);
        send_bytes(c, r, 8);
        plat_sleep_ms(20);
        send_bytes(c, r + 8, 7);
        memcpy(r, "\x16\x03\x03\x00\x20", 5);
        memcpy(r + 5, sh + 10, 32);
        send_bytes(c, r, 37);
        send_bytes(c, "\x17\x03\x03\x00\x02\x01\x02", 7);
        drain(c);
        break;
    }
    case M_ECHO:
        send_bytes(c, req, n);
        break;
    case M_DNS_TCP: {
        /* answer the query in req (2-byte length prefix) with 1.2.3.4 */
        uint8_t r[512];
        size_t ql = n >= 2 ? (size_t)req[0] << 8 | req[1] : 0, k;
        if (ql + 2 > n || ql < 12 || ql > 400)
            break;
        memcpy(r + 2, req + 2, ql);
        r[2 + 2] = 0x81;
        r[2 + 3] = 0x80;
        r[2 + 7] = 1; /* ANCOUNT */
        k = 2 + ql;
        memcpy(r + k, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x01\x02\x03\x04", 16);
        k += 16;
        r[0] = (uint8_t)((k - 2) >> 8);
        r[1] = (uint8_t)(k - 2);
        send_bytes(c, r, k);
        drain(c);
        break;
    }
    }
}

static void server_main(void *arg)
{
    (void)arg;
    while (!srv.stop) {
        struct sockaddr_storage peer;
        socklen_t pl = sizeof(peer);
        sock_t c = accept(srv.ls, (struct sockaddr *)&peer, &pl);
        if (c == SOCK_INVALID)
            continue;
        if (srv.stop) {
            plat_sock_close(c);
            break;
        }
        srv.peer_port = ntohs(((struct sockaddr_in *)&peer)->sin_port);
        serve_one(c);
        plat_sock_close(c);
    }
}

static int server_start(void)
{
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    int one = 1;
    srv.ls = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(srv.ls, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv.ls, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(srv.ls, 16) < 0)
        return -1;
    getsockname(srv.ls, (struct sockaddr *)&a, &al);
    srv.port = ntohs(a.sin_port);
    srv.stop = 0;
    return plat_thread_start(&srv.th, server_main, NULL);
}

static void server_stop(void)
{
    sock_t s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    srv.stop = 1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(srv.port);
    connect(s, (struct sockaddr *)&a, sizeof(a)); /* wakes accept() */
    plat_thread_join(srv.th);
    plat_sock_close(s);
    plat_sock_close(srv.ls);
}

static void cfg_init(probe_cfg *c, probe_kind k, uint16_t port)
{
    sbuf err;
    memset(c, 0, sizeof(*c));
    c->kind = k;
    c->host = "test.example";
    c->ip = "127.0.0.1";
    c->port = port;
    c->timeout = 2;
    sb_init(&err);
    if (probe_resolve(c, &err) < 0)
        fprintf(stderr, "resolve: %s\n", err.data);
    sb_free(&err);
}

static probe_outcome run_mode(int mode, probe_cfg *c, probe_res *r)
{
    probe_ports lp = {0, 0, 0};
    srv.mode = mode;
    probe_run(c, &lp, r);
    return r->outcome;
}

static void test_http(void)
{
    probe_cfg c;
    probe_res r;
    t_current = "probe http";
    cfg_init(&c, PROBE_HTTP, srv.port);
    CHECK_INT(run_mode(M_HTTP_CL, &c, &r), PO_OK);
    CHECK(r.fitness == 400);
    CHECK_INT(run_mode(M_HTTP_CHUNKED, &c, &r), PO_OK);
    CHECK_INT(run_mode(M_HTTP_EOF, &c, &r), PO_OK);
    CHECK_INT(run_mode(M_HTTP_PARTIAL, &c, &r), PO_BROKEN);
    CHECK(r.fitness == -480);
    CHECK_INT(run_mode(M_RESET, &c, &r), PO_RESET);
    CHECK(r.fitness == -360);
    c.timeout = 0.3;
    CHECK_INT(run_mode(M_SILENT, &c, &r), PO_TIMEOUT);
    c.timeout = 2;
    CHECK_INT(run_mode(M_HTTP_BLOCK, &c, &r), PO_OK); /* 403 is still a complete answer */
    c.injected_contains = "blocked by";
    CHECK_INT(run_mode(M_HTTP_BLOCK, &c, &r), PO_INJECTED);
    CHECK_INT(run_mode(M_HTTP_CL, &c, &r), PO_OK);
    c.injected_contains = NULL;
    c.valid_contains = "hello";
    CHECK_INT(run_mode(M_HTTP_CL, &c, &r), PO_OK);
    c.valid_contains = "absent";
    CHECK_INT(run_mode(M_HTTP_CL, &c, &r), PO_BROKEN);
    c.valid_contains = NULL;
    c.min_bytes = 10000;
    CHECK_INT(run_mode(M_HTTP_EOF, &c, &r), PO_BROKEN);

    /* nothing listens (Windows retries a refused connect for about 2 s) */
    cfg_init(&c, PROBE_HTTP, 1);
    c.timeout = 8;
    {
        probe_ports lp = {0, 0, 0};
        probe_run(&c, &lp, &r);
        CHECK_INT(r.outcome, PO_RESET);
    }
}

static void test_tls(void)
{
    probe_cfg c;
    probe_res r;
    uint8_t ch[1024];
    size_t n;
    t_current = "probe tls";
    /* the ClientHello: record and handshake lengths, SNI inside */
    n = probe_client_hello("blocked.example", "http/1.1", 0, ch, sizeof(ch));
    CHECK(n > 100);
    CHECK_INT(ch[0], 0x16);
    CHECK_INT((size_t)ch[3] << 8 | ch[4], n - 5);
    CHECK_INT(ch[5], 1);
    CHECK_INT((size_t)ch[7] << 8 | ch[8], n - 9);
    {
        int found = 0;
        for (size_t i = 0; i + 15 <= n; i++)
            found |= !memcmp(ch + i, "blocked.example", 15);
        CHECK(found);
    }
    CHECK(probe_client_hello("x", NULL, 12, ch, sizeof(ch)) < n);
    CHECK_INT(probe_client_hello("x", NULL, 0, ch, 100), 0);

    cfg_init(&c, PROBE_TLS, srv.port);
    CHECK_INT(run_mode(M_TLS13, &c, &r), PO_OK);
    CHECK_INT(run_mode(M_TLS12, &c, &r), PO_OK);
    CHECK_INT(run_mode(M_TLS_SPLIT, &c, &r), PO_OK);
    CHECK_INT(run_mode(M_HTTP_EOF, &c, &r), PO_BROKEN); /* not TLS */
    CHECK_INT(run_mode(M_RESET, &c, &r), PO_RESET);
    c.timeout = 0.3;
    CHECK_INT(run_mode(M_SILENT, &c, &r), PO_TIMEOUT);
    c.timeout = 2;
    c.min_bytes = 5000;
    CHECK_INT(run_mode(M_TLS13, &c, &r), PO_BROKEN);
}

static void test_tcp_ports(void)
{
    probe_cfg c;
    probe_res r;
    probe_ports lp = {40100, 40103, 0};
    int p1, p2;
    t_current = "probe tcp + local ports";
    cfg_init(&c, PROBE_TCP, srv.port);
    CHECK(probe_parse_payload("ping\\r\\n\\x41", &c.payload, &c.payload_len) == 0);
    CHECK_INT(c.payload_len, 7);
    CHECK(!memcmp(c.payload, "ping\r\nA", 7));
    c.valid_contains = "ping";
    srv.mode = M_ECHO;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    p1 = srv.peer_port;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    p2 = srv.peer_port;
    CHECK(p1 >= 40100 && p1 <= 40103);
    CHECK(p2 >= 40100 && p2 <= 40103);
    CHECK(p1 != p2); /* rotated: no TIME_WAIT reuse */
    c.valid_contains = "pong";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_BROKEN);
    free(c.payload);

    {
        uint8_t *b;
        size_t n;
        CHECK(probe_parse_payload("hex:0a0B", &b, &n) == 0);
        CHECK(n == 2 && b[0] == 10 && b[1] == 11);
        free(b);
        CHECK(probe_parse_payload("bad\\q", &b, &n) < 0);
        CHECK(probe_parse_payload("bad\\x4", &b, &n) < 0);
    }
}

/* ---- dns ----------------------------------------------------------------- */

static struct {
    sock_t s;
    uint16_t port;
    volatile int stop, mode; /* 0 = 1.2.3.4, 1 = 10.10.10.10, 2 = NXDOMAIN, 3 = garbage then 1.2.3.4 */
    plat_thread_t th;
} dns;

static void dns_main(void *arg)
{
    (void)arg;
    while (!dns.stop) {
        uint8_t q[512], r[600];
        struct sockaddr_storage from;
        socklen_t fl = sizeof(from);
        plat_pollfd p = {0};
        int n;
        size_t k;
        p.fd = dns.s;
        p.events = POLLIN;
        if (plat_poll(&p, 1, 50) <= 0)
            continue;
        n = (int)recvfrom(dns.s, (char *)q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
        if (n < 12)
            continue;
        if (dns.mode == 3) /* an answer with another id first */
            sendto(dns.s, "\xde\xad\x81\x80\x00\x00\x00\x00\x00\x00\x00\x00", 12, 0, (struct sockaddr *)&from, fl);
        memcpy(r, q, (size_t)n);
        r[2] = 0x81;
        r[3] = dns.mode == 2 ? 0x83 : 0x80;
        r[7] = dns.mode == 2 ? 0 : 1;
        k = (size_t)n;
        if (dns.mode != 2) {
            memcpy(r + k, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04", 12);
            k += 12;
            memcpy(r + k, dns.mode == 1 ? "\x0a\x0a\x0a\x0a" : "\x01\x02\x03\x04", 4);
            k += 4;
        }
        sendto(dns.s, (const char *)r, (int)k, 0, (struct sockaddr *)&from, fl);
    }
}

static void test_dns(void)
{
    probe_cfg c;
    probe_res r;
    probe_ports lp = {0, 0, 0};
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    uint8_t q[300];
    char out[4][46];
    int rcode;
    t_current = "probe dns";

    /* query building and answer parsing */
    {
        size_t n = probe_dns_query("www.example.com", 0, 0x1234, q, sizeof(q));
        CHECK_INT(n, 12 + 17 + 4);
        CHECK(!memcmp(q + 12, "\x03" "www" "\x07" "example" "\x03" "com" "\x00\x00\x01\x00\x01", 21));
        /* the same query answered with a compressed A record */
        q[2] = 0x81;
        q[3] = 0x80;
        q[7] = 1;
        memcpy(q + n, "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22", 16);
        CHECK_INT(probe_dns_parse(q, n + 16, 0x1234, out, 4, &rcode), 1);
        CHECK_STR(out[0], "93.184.216.34");
        CHECK_INT(rcode, 0);
        CHECK_INT(probe_dns_parse(q, n + 16, 0x1235, out, 4, &rcode), -1);
        CHECK_INT(probe_dns_parse(q, n + 10, 0x1234, out, 4, &rcode), -1);
        CHECK_INT(probe_dns_query("a..b", 0, 1, q, sizeof(q)), 0);
    }

    dns.s = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(dns.s, (struct sockaddr *)&a, sizeof(a)) < 0) {
        CHECK(!"bind");
        return;
    }
    getsockname(dns.s, (struct sockaddr *)&a, &al);
    dns.port = ntohs(a.sin_port);
    plat_thread_start(&dns.th, dns_main, NULL);

    cfg_init(&c, PROBE_DNS, dns.port);
    c.host = "blocked.example";
    dns.mode = 0;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    CHECK_STR(r.detail, "1.2.3.4");
    dns.mode = 3;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK); /* answers with another id are not ours */
    dns.mode = 1;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK); /* nothing says it is forged */
    c.dns_bad = "192.0.2.1,10.0.0.0/8";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_INJECTED);
    c.dns_bad = NULL;
    c.dns_expect = "1.2.3.0/24";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_INJECTED);
    dns.mode = 0;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    dns.mode = 2;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_INJECTED); /* NXDOMAIN for a name that exists */

    /* over TCP */
    cfg_init(&c, PROBE_DNS, srv.port);
    c.host = "blocked.example";
    c.dns_tcp = 1;
    srv.mode = M_DNS_TCP;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    CHECK_STR(r.detail, "1.2.3.4");
    c.timeout = 0.3;
    srv.mode = M_SILENT;
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_TIMEOUT);

    dns.stop = 1;
    plat_thread_join(dns.th);
    plat_sock_close(dns.s);
}

/* ---- exec ---------------------------------------------------------------- */

static void test_exec(void)
{
    probe_cfg c;
    probe_res r;
    probe_ports lp = {31000, 31063, 0};
    sbuf s;
    t_current = "probe exec";
    cfg_init(&c, PROBE_EXEC, 8080);
    c.cmd = "x {lports} {lport} {host} {ip} {port} {other}";
    sb_init(&s);
    probe_expand_cmd(&c, &lp, &s);
    CHECK_STR(s.data, "x 31000-31063 31000 test.example 127.0.0.1 8080 {other}");
    sb_free(&s);

    c.cmd = "exit 0";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    c.cmd = "exit 3";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_FAILED);
#ifdef _WIN32
    c.cmd = "echo Connection reset by peer & exit 7";
#else
    c.cmd = "echo 'Connection reset by peer'; exit 7";
#endif
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_RESET);
    c.cmd = "echo the page";
    c.valid_contains = "page";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_OK);
    c.valid_contains = "nothing";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_BROKEN);
    c.valid_contains = NULL;
    c.injected_contains = "page";
    probe_run(&c, &lp, &r);
    CHECK_INT(r.outcome, PO_INJECTED);
    c.injected_contains = NULL;
#ifdef _WIN32
    c.cmd = "ping -n 6 127.0.0.1 >nul";
#else
    c.cmd = "sleep 5";
#endif
    c.timeout = 0.5;
    {
        uint64_t t0 = plat_now_ms();
        probe_run(&c, &lp, &r);
        CHECK_INT(r.outcome, PO_FAILED);
        CHECK(plat_now_ms() - t0 < 3000);
    }
}

/* ---- evaluator ----------------------------------------------------------- */

static void test_punish(void)
{
    sbuf err;
    strategy *s;
    t_current = "eval punish";
    sb_init(&err);
    s = strategy_parse("[TCP:flags:PA]-duplicate(tamper{TCP:flags:replace:S},)-| \\/", &err);
    CHECK(s != NULL);
    if (!s)
        return;
    /* two actions; the tree never fired; overhead 5 */
    CHECK(eval_punish(400, s, 5) == 400 - 2 - 10 - 2);
    s->out[0]->fired = 1;
    CHECK(eval_punish(400, s, 5) == 400 - 2 - 2);
    CHECK(eval_punish(-360, s, 5) == -360);
    s->out[0]->fired = 0;
    CHECK(eval_punish(-360, s, 5) == -370);
    CHECK(eval_punish(5, s, 0) == 5 - 2 - 10);
    CHECK(eval_punish(400, NULL, 9) == 400);
    strategy_free(s);
    sb_free(&err);
}

static void test_evaluator(void)
{
    eval_opts o;
    evaluator *ev = NULL;
    eval_result r;
    sbuf err;
    int reachable = 0;
    t_current = "evaluator (no engine)";
    eval_opts_default(&o);
    cfg_init(&o.probe, PROBE_HTTP, srv.port);
    o.use_engine = 0;
    o.runs = 3;
    sb_init(&err);
    CHECK_INT(evaluator_open(&o, &ev, &err), 0);
    srv.mode = M_HTTP_CL;
    CHECK_INT(evaluator_baseline(ev, &r, &reachable, NULL, NULL), 0);
    CHECK(reachable);
    CHECK_INT(r.runs, 3);
    CHECK(r.fitness == 400);
    srv.mode = M_RESET;
    CHECK_INT(evaluator_eval(ev, "", &r), 0);
    CHECK(r.fitness == -360);
    CHECK_INT(r.last.outcome, PO_RESET);
    o.by = FIT_MAX;
    CHECK_INT(evaluator_eval(ev, NULL, &r), 0);
    CHECK(r.fitness == -360);
    /* the GA batch: an empty strategy is skipped (Geneva's skip_empty) */
    {
        ga_ind inds[2];
        memset(inds, 0, sizeof(inds));
        inds[0].s = strategy_parse(" \\/", &err);
        inds[0].str = " \\/";
        inds[1].s = strategy_parse(" \\/ ", &err);
        inds[1].str = " \\/ ";
        o.runs = 1;
        srv.mode = M_HTTP_CL;
        CHECK_INT(evaluator_ga(ev, inds, 2), 0);
        CHECK(inds[0].fit == -1000 && inds[1].fit == -1000);
        o.skip_empty = 0;
        o.workers = 1;
        CHECK_INT(evaluator_ga(ev, inds, 2), 0);
        CHECK(inds[0].fit == 400 && inds[1].fit == 400);
        o.workers = 2;
        inds[0].fit = inds[1].fit = 0;
        CHECK_INT(evaluator_ga(ev, inds, 2), 0);
        CHECK(inds[0].fit == 400 && inds[1].fit == 400);
        strategy_free(inds[0].s);
        strategy_free(inds[1].s);
    }
    {
        volatile sig_atomic_t stop = 1;
        o.stop = &stop;
        CHECK_INT(evaluator_eval(ev, "", &r), -1);
        o.stop = NULL;
    }
    evaluator_close(ev);
    sb_free(&err);
}

void suite_probe(void)
{
    if (server_start() != 0) {
        t_current = "probe server";
        CHECK(!"cannot start the test server");
        return;
    }
    test_http();
    test_tls();
    test_tcp_ports();
    test_dns();
    test_exec();
    test_punish();
    test_evaluator();
    server_stop();
}
