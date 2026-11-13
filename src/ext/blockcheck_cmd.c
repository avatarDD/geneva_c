/*
 * "geneva blockcheck --ext" (blockcheck.h): blockcheck2.sh's main loop over
 * domains, IP versions and tests; each test checks the domain without a
 * strategy first, then runs the grid through the evaluator.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmd_eval.h"
#include "evaluator.h"
#include "ext/blockcheck.h"
#include "ext_opt.h"
#include "geneva.h"
#include "log.h"
#include "plat.h"

#ifndef _WIN32
#  include <netdb.h>
#endif

typedef struct {
    evaluator *ev;
    int repeats, level;
    FILE *log;
} bc_cmd;

/* curl_test: REPEATS attempts, quick levels stop at the first failure */
static int attempts(bc_cmd *c, const char *gen)
{
    int fail = 0;
    for (int n = 0; n < c->repeats; n++) {
        eval_result r;
        if (evaluator_eval(c->ev, gen, &r) < 0)
            return -1;
        if (c->log)
            fprintf(c->log, "%s%s: %s\n", c->repeats > 1 ? "[attempt] " : "", probe_outcome_name(r.last.outcome),
                    r.last.detail);
        if (r.last.outcome != PO_OK) {
            fail = 1;
            if (c->level == BC_QUICK || c->level == BC_VERYQUICK)
                break;
        }
    }
    return !fail;
}

static int test_fn(void *ctx, const char *nfqws2, const char *gen)
{
    (void)nfqws2;
    if (!gen)
        return 0;
    return attempts(ctx, gen);
}

/* --print-grid: the lines of --grid-ok work, the rest fail */
typedef struct {
    char **ok;
    size_t n;
} grid_oracle;

static int print_fn(void *ctx, const char *nfqws2, const char *gen)
{
    const grid_oracle *g = ctx;
    printf("%s\t%s\n", nfqws2, gen ? gen : "-");
    for (size_t i = 0; i < g->n; i++)
        if (!strcmp(g->ok[i], nfqws2))
            return 1;
    return 0;
}

static int read_oracle(const char *path, grid_oracle *g)
{
    size_t len;
    char *text = read_file(path, &len), *line, *next;
    if (!text) {
        fprintf(stderr, "geneva blockcheck: cannot read %s\n", path);
        return -1;
    }
    for (line = text; line && *line; line = next) {
        char *e;
        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        e = line + strlen(line);
        while (e > line && (e[-1] == '\r' || e[-1] == ' '))
            *--e = 0;
        if (!*line)
            continue;
        g->ok = xrealloc(g->ok, (g->n + 1) * sizeof(*g->ok));
        g->ok[g->n++] = xstrdup(line);
    }
    free(text);
    return 0;
}

/* a comma list into a new array */
static int split_list(const char *s, char ***out)
{
    char *copy = xstrdup(s), *p = copy;
    int n = 0;
    *out = NULL;
    while (p && *p) {
        char *e = strchr(p, ',');
        if (e)
            *e++ = 0;
        if (*p) {
            *out = xrealloc(*out, (size_t)(n + 1) * sizeof(**out));
            (*out)[n++] = xstrdup(p);
        }
        p = e;
    }
    free(copy);
    return n;
}

static void free_list(char **l, int n)
{
    for (int i = 0; i < n; i++)
        free(l[i]);
    free(l);
}

static int name_ok(const char *d)
{
    /* names go into curl's command line (http3, DoH) and the Host header */
    return *d && strspn(d, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") == strlen(d);
}

/* the probe of test t for dom at ip, as curl_test_* */
static void setup_probe(probe_cfg *p, int t, const char *dom, const char *ip, int ipv, double timeout, const char *curl,
                        char *cmdline, size_t cap)
{
    memset(p, 0, sizeof(*p));
    p->host = dom;
    p->ip = ip;
    p->timeout = timeout;
    p->path = "/";
    p->max_bytes = 4u << 20;
    switch (t) {
    case BC_HTTP:
        p->kind = PROBE_HTTP;
        p->port = 80;
        p->strict_http = 1;
        break;
    case BC_TLS12:
    case BC_TLS13:
        p->kind = PROBE_TLS;
        p->port = 443;
        p->tls_version = t == BC_TLS12 ? 12 : 13;
        break;
    default:
        p->kind = PROBE_EXEC;
        p->port = 443;
        snprintf(cmdline, cap,
                 "%s --http3-only -Ss --max-time %g --local-port {lports} --connect-to %s::%s%s%s:443 -o %s https://%s",
                 curl, timeout, dom, ipv == 6 ? "[" : "", ip, ipv == 6 ? "]" : "",
#ifdef _WIN32
                 "NUL",
#else
                 "/dev/null",
#endif
                 dom);
        p->cmd = cmdline;
        p->timeout = timeout + 5;
        break;
    }
}

/* curl_test without the engine (check_dpi_ip_block): 1 when every attempt
 * gets through; detail: the HTTP answer is not judged (curl_test_http's
 * "detail" prints it instead) */
static int direct_test(const bc_cmd *c, int t, const char *dom, const char *ip, int ipv, double timeout, int detail,
                       char *what, size_t cap)
{
    probe_cfg p;
    probe_ports lp = {0, 0, 0};
    probe_res r;
    sbuf err;
    char cmdline[8];
    int ok = 1;
    setup_probe(&p, t, dom, ip, ipv, timeout, "curl", cmdline, sizeof(cmdline));
    p.strict_http = !detail;
    sb_init(&err);
    if (probe_resolve(&p, &err) < 0) {
        snprintf(what, cap, "%s", err.data ? err.data : "bad address");
        sb_free(&err);
        return 0;
    }
    sb_free(&err);
    for (int n = 0; n < c->repeats; n++) {
        probe_run(&p, &lp, &r);
        snprintf(what, cap, "%s: %s", probe_outcome_name(r.outcome), r.detail);
        if (c->log)
            fprintf(c->log, "%s%s\n", c->repeats > 1 ? "[attempt] " : "", what);
        if (r.outcome != PO_OK) {
            ok = 0;
            if (c->level == BC_QUICK || c->level == BC_VERYQUICK)
                break;
        }
    }
    return ok;
}

static void add_check(bc_run *b, const char *kind, const char *test, const char *dom, const char *ip,
                      const char *owner, int port, int ok, const char *detail)
{
    bc_check c;
    memset(&c, 0, sizeof(c));
    c.kind = (char *)kind;
    c.test = (char *)test;
    c.ipv = b->ipv;
    c.domain = (char *)dom;
    c.ip = (char *)ip;
    c.owner = (char *)owner;
    c.port = port;
    c.ok = ok;
    c.detail = (char *)detail;
    bc_add_check(b, &c);
}

/* check_domain_port_block */
static void port_block(bc_run *b, bc_resolver *res, const char *dom, const char *fixed_ip, int port)
{
    bc_ip ips[BC_MAXIP];
    int n;
    if (b->log)
        fprintf(b->log, "\n* port block tests ipv%d %s:%d\n", b->ipv, dom, port);
    if (fixed_ip) {
        snprintf(ips[0], sizeof(ips[0]), "%s", fixed_ip);
        n = 1;
    } else {
        n = bc_resolve_all(res, dom, b->ipv, ips, BC_MAXIP);
    }
    if (n <= 0) {
        if (b->log)
            fprintf(b->log, "ipv%d %s does not resolve\n", b->ipv, dom);
        return;
    }
    for (int i = 0; i < n; i++) {
        char detail[200];
        int ok = bc_port_open(ips[i], (uint16_t)port, 2, detail, sizeof(detail));
        if (b->log) {
            if (ok)
                fprintf(b->log, "%s connects\n", ips[i]);
            else
                fprintf(b->log, "%s does not connect: %s\n", ips[i], detail);
        }
        add_check(b, "port", NULL, dom, ips[i], NULL, port, ok, detail);
    }
}

/* check_dpi_ip_block, with geneva's reading of the results */
static void ip_block(bc_run *b, const bc_cmd *c, bc_resolver *res, int t, const char *dom, const char *fixed_ip,
                     const char *unblocked, double timeout)
{
    bc_ip uip[BC_MAXIP], bips[BC_MAXIP];
    char what[300];
    int n, ok;
    FILE *log = b->log;

    if (log)
        fprintf(log, "\n- IP block tests (requires manual interpretation)\n> testing %s on it's original ip\n",
                unblocked);
    n = bc_resolve_all(res, unblocked, b->ipv, uip, BC_MAXIP);
    if (n <= 0) {
        if (log)
            fprintf(log, "%s does not resolve. tests not possible.\n", unblocked);
        return;
    }
    if (!direct_test(c, t, unblocked, uip[0], b->ipv, timeout, 0, what, sizeof(what))) {
        if (log)
            fprintf(log, "%s is not available. skipping this test.\n", unblocked);
        return;
    }
    if (log)
        fprintf(log, "> testing %s on %s (%s)\n", dom, uip[0], unblocked);
    ok = direct_test(c, t, dom, uip[0], b->ipv, timeout, 1, what, sizeof(what));
    add_check(b, "ip", b->testf, dom, uip[0], unblocked, 0, ok, what);
    if (log)
        fprintf(log, ok ? "  geneva: %s gets through on another address: the block is by its IP\n"
                        : "  geneva: %s is blocked on another address too: the block is by its name (DPI)\n",
                dom);
    if (fixed_ip) {
        snprintf(bips[0], sizeof(bips[0]), "%s", fixed_ip);
        n = 1;
    } else {
        n = bc_resolve_all(res, dom, b->ipv, bips, BC_MAXIP);
    }
    for (int i = 0; i < n; i++) {
        if (log)
            fprintf(log, "> testing %s on %s (%s)\n", unblocked, bips[i], dom);
        ok = direct_test(c, t, unblocked, bips[i], b->ipv, timeout, 1, what, sizeof(what));
        add_check(b, "ip", b->testf, unblocked, bips[i], dom, 0, ok, what);
        if (log)
            fprintf(log, ok ? "  geneva: %s lets another name through: no block by address\n"
                            : "  geneva: %s blocks another name too: the address is blocked\n",
                    bips[i]);
    }
}

static int parse_list(const char *s, const char *const *names, int n, int *on, const char *what)
{
    char *copy = xstrdup(s), *p = copy;
    while (p && *p) {
        char *e = strchr(p, ',');
        int i;
        if (e)
            *e++ = 0;
        for (i = 0; i < n && strcmp(names[i], p); i++)
            ;
        if (i == n) {
            fprintf(stderr, "geneva blockcheck: %s: unknown %s (%s)\n", p, what, s);
            free(copy);
            return -1;
        }
        on[i] = 1;
        p = e;
    }
    free(copy);
    return 0;
}

int xcmd_blockcheck(int argc, char **argv)
{
    static const optdef defs[] = {
        {"domain", 'd', 1, "NAME,..", "domains to check (repeatable; default rutracker.org)"},
        {"test", 0, 1, "LIST", "http, tls12, tls13, http3 (default http,tls12)"},
        {"ip", 0, 1, "ADDR", "connect to ADDR instead of the domain's address (as curl --connect-to)"},
        {"scripts", 0, 1, "N,..", "only these scripts of the grid: 10, 15, 17, 20, 23, 24, 25, 30, 35, 50, 55, 60, 90"},
        {"ipv", 0, 1, "4|6|46", "IP versions (default 4)"},
        {"level", 0, 1, "LEVEL", "scan level: quick, standard (default), force or veryquick"},
        {"repeats", 0, 1, "N", "attempts of each test, all must succeed (default 1)"},
        {"min-ttl", 0, 1, "N", "the fakes' TTL from (1)"},
        {"max-ttl", 0, 1, "N", "... to (12; 0: no TTL tests)"},
        {"min-autottl-delta", 0, 1, "N", "the autottl delta from (1)"},
        {"max-autottl-delta", 0, 1, "N", "... to (5; 0: no autottl tests)"},
        {"fake-repeats", 0, 1, "N", "repeats of each fake (1)"},
        {"multidisorder-legacy", 0, 0, NULL, "multidisorder_legacy instead of multidisorder"},
        {"timeout", 0, 1, "SEC", "the probe's timeout (default 2, as CURL_MAX_TIME)"},
        {"curl", 0, 1, "PATH", "the curl for http3 (with HTTP/3) and DoH (default curl)"},
        {"skip-dnscheck", 0, 0, NULL, "no DNS check (SKIP_DNSCHECK)"},
        {"dns-servers", 0, 1, "IP,..", "public DNS for the check (default 8.8.8.8,1.1.1.1,77.88.8.1)"},
        {"dns-domains", 0, 1, "NAME,..", "domains of the check (default pornhub.com,ej.ru,rutracker.org,"
                                         "www.torproject.org,bbc.com)"},
        {"secure-dns", 0, 1, "0|1", "resolve through DoH: 1 always, 0 never (default: when DNS is spoofed)"},
        {"doh", 0, 1, "URL", "this DoH server, without a search (DOH_SERVER)"},
        {"doh-servers", 0, 1, "URL,..", "DoH servers to search (default cloudflare, google, quad9, adguard, yandex)"},
        {"skip-ipblock", 0, 0, NULL, "no IP and port block tests (SKIP_IPBLOCK)"},
        {"unblocked-domain", 0, 1, "NAME", "the IP block tests' unblocked domain (default iana.org)"},
        {"json", 0, 0, NULL, "the report as JSON on stdout"},
        {"print-grid", 0, 0, NULL, "no probes: print the grid's lines (nfqws2<TAB>geneva) as if all failed"},
        {"grid-ok", 0, 1, "FILE", "--print-grid: the nfqws2 lines of FILE work (the grid's shortcuts follow)"},
        {"quiet", 0, 0, NULL, "no progress on stderr"},
        {"local-ports", 0, 1, "BASE", "the probes' local ports: 64 from BASE (default 30000)"},
        {"queue", 'q', 1, "N", "NFQUEUE number (default 311)"},
        {"mark", 0, 1, "MASK", "fwmark of packets the engine sends (default 0x20000000)"},
        {"firewall", 0, 1, "TYPE", "auto, nft or iptables"},
        {"log-level", 'l', 1, "LEVEL", "error, warn (default), info, debug or trace"},
        EXT_OPT,
        EXT_CTRACK_OPTS,
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    static const char *const test_opt[BC_NTESTS] = {"http", "tls12", "tls13", "http3"};
    static const char *const level_opt[] = {"veryquick", "quick", "standard", "force"};
    static volatile sig_atomic_t stop;
    static const char doh_default[] = "https://cloudflare-dns.com/dns-query,https://dns.google/dns-query,"
                                      "https://dns.quad9.net/dns-query,https://dns.adguard.com/dns-query,"
                                      "https://common.dot.dns.yandex.net/dns-query";
    args_t a;
    char aerr[128];
    int tests[BC_NTESTS] = {0}, rc = EXIT_USAGE, idx = 0, found = 0, print, ipvs[2], nipv = 0;
    int64_t v;
    double timeout;
    const char *s, *curl, *fixed_ip, *unblocked;
    char **doms = NULL, **dns_servers = NULL, **dns_domains = NULL, **dohs = NULL;
    int ndom = 0, ndns_servers = 0, ndns_domains = 0, ndohs = 0, secure = -1, skip_ipblock;
    bc_resolver res;
    bc_run b;
    bc_cmd cmd;
    eval_opts o;
    grid_oracle oracle = {NULL, 0};

    bc_init(&b);
    memset(&cmd, 0, sizeof(cmd));
    memset(&res, 0, sizeof(res));
    if (args_parse(&a, argc, argv, defs, aerr, sizeof(aerr)) < 0) {
        fprintf(stderr, "geneva blockcheck: %s\n", aerr);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva blockcheck --ext [options] [DOMAIN...]\n"
                  "zapret2's blockcheck2 with geneva: each test (HTTP, TLS 1.2, TLS 1.3, HTTP/3)\n"
                  "of each domain is checked without a strategy, then with the strategies of\n"
                  "blockcheck2.d/standard (split, disorder, seqovl, syndata, oob, fakes with TTL,\n"
                  "autottl and foolings, faked splits, hostfake, QUIC fakes and fragments), each\n"
                  "nfqws2 line translated into a geneva strategy, in the scripts' order and with\n"
                  "their shortcuts. The report: SUMMARY (the working lines of each test, with\n"
                  "their geneva strategies), and for several domains COMMON (working for all)\n"
                  "and COVERAGE. Before the tests, as blockcheck2: the DNS check (the system\n"
                  "resolver against public DNS; spoofed DNS switches the tests to DoH through\n"
                  "curl), and for each domain the port block test and, when the domain is\n"
                  "blocked, the IP block tests (the domain on an unblocked domain's address and\n"
                  "back). Exit code 0 when something works, 1 otherwise.\n"
                  "Needs root (Administrator), except with --print-grid.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (!arg_has(&a, "ext")) {
        fprintf(stderr, "geneva blockcheck: needs --ext\n");
        args_free(&a);
        return EXIT_USAGE;
    }
    if (ext_parse_args(&a, "blockcheck") < 0)
        goto done;
    if (parse_logging(&a, "blockcheck") < 0)
        goto done;
    if (!arg_has(&a, "log-level"))
        log_set_level(LOG_WARN);
    print = arg_has(&a, "print-grid");
    if (parse_list(arg_str(&a, "test", "http,tls12"), test_opt, BC_NTESTS, tests, "test") < 0)
        goto done;
    s = arg_str(&a, "level", "standard");
    for (b.level = 0; b.level < 4 && strcmp(level_opt[b.level], s); b.level++)
        ;
    if (b.level == 4) {
        fprintf(stderr, "geneva blockcheck: --level is veryquick, quick, standard or force\n");
        goto done;
    }
    s = arg_str(&a, "ipv", "4");
    if (!strcmp(s, "4") || !strcmp(s, "6")) {
        ipvs[nipv++] = *s - '0';
    } else if (!strcmp(s, "46")) {
        ipvs[nipv++] = 4;
        ipvs[nipv++] = 6;
    } else {
        fprintf(stderr, "geneva blockcheck: --ipv is 4, 6 or 46\n");
        goto done;
    }
    if (arg_int(&a, "repeats", 1, 1, 100, &v) < 0)
        goto done;
    cmd.repeats = (int)v;
    if (arg_int(&a, "min-ttl", 1, 1, 255, &v) < 0)
        goto done;
    b.min_ttl = (int)v;
    if (arg_int(&a, "max-ttl", 12, 0, 255, &v) < 0)
        goto done;
    b.max_ttl = (int)v;
    if (arg_int(&a, "min-autottl-delta", 1, 1, 255, &v) < 0)
        goto done;
    b.min_autottl = (int)v;
    if (arg_int(&a, "max-autottl-delta", 5, 0, 255, &v) < 0)
        goto done;
    b.max_autottl = (int)v;
    if (arg_int(&a, "fake-repeats", 1, 1, 1000, &v) < 0)
        goto done;
    b.fake_repeats = (int)v;
    b.multidisorder_legacy = arg_has(&a, "multidisorder-legacy");
    if (arg_dbl(&a, "timeout", 2, 0.1, 600, &timeout) < 0)
        goto done;
    curl = arg_str(&a, "curl", "curl");
    fixed_ip = arg_str(&a, "ip", NULL);
    if ((s = arg_str(&a, "scripts", NULL)) != NULL) {
        sbuf err;
        sb_init(&err);
        if (bc_select_scripts(&b, s, &err) < 0) {
            fprintf(stderr, "geneva blockcheck: --scripts: %s\n", err.data);
            sb_free(&err);
            goto done;
        }
        sb_free(&err);
    }
    while ((s = arg_next(&a, "domain", &idx)) != NULL) {
        char *copy = xstrdup(s), *p = copy;
        while (p && *p) {
            char *e = strchr(p, ',');
            if (e)
                *e++ = 0;
            if (*p) {
                doms = xrealloc(doms, (size_t)(ndom + 1) * sizeof(*doms));
                doms[ndom++] = xstrdup(p);
            }
            p = e;
        }
        free(copy);
    }
    for (int i = 0; i < a.npos; i++) {
        doms = xrealloc(doms, (size_t)(ndom + 1) * sizeof(*doms));
        doms[ndom++] = xstrdup(a.pos[i]);
    }
    if (!ndom) {
        doms = xmalloc(sizeof(*doms));
        doms[ndom++] = xstrdup("rutracker.org");
    }
    for (int i = 0; i < ndom; i++)
        if (!name_ok(doms[i])) {
            fprintf(stderr, "geneva blockcheck: bad domain %s\n", doms[i]);
            goto done;
        }
    ndns_servers = split_list(arg_str(&a, "dns-servers", "8.8.8.8,1.1.1.1,77.88.8.1"), &dns_servers);
    ndns_domains = split_list(arg_str(&a, "dns-domains", "pornhub.com,ej.ru,rutracker.org,www.torproject.org,bbc.com"),
                              &dns_domains);
    for (int i = 0; i < ndns_domains; i++)
        if (!name_ok(dns_domains[i])) {
            fprintf(stderr, "geneva blockcheck: bad domain %s\n", dns_domains[i]);
            goto done;
        }
    ndohs = split_list(arg_str(&a, "doh-servers", doh_default), &dohs);
    for (int i = 0; i < ndohs; i++)
        if (!bc_doh_url_ok(dohs[i])) {
            fprintf(stderr, "geneva blockcheck: bad DoH URL %s\n", dohs[i]);
            goto done;
        }
    if ((s = arg_str(&a, "doh", NULL)) != NULL && !bc_doh_url_ok(s)) {
        fprintf(stderr, "geneva blockcheck: bad DoH URL %s\n", s);
        goto done;
    }
    if ((s = arg_str(&a, "secure-dns", NULL)) != NULL) {
        if (strcmp(s, "0") && strcmp(s, "1")) {
            fprintf(stderr, "geneva blockcheck: --secure-dns is 0 or 1\n");
            goto done;
        }
        secure = *s - '0';
    }
    unblocked = arg_str(&a, "unblocked-domain", "iana.org");
    if (!name_ok(unblocked)) {
        fprintf(stderr, "geneva blockcheck: bad domain %s\n", unblocked);
        goto done;
    }
    skip_ipblock = arg_has(&a, "skip-ipblock");
    cmd.level = b.level;
    cmd.log = b.log = arg_has(&a, "quiet") || print ? NULL : stderr;

    if (print) {
        if ((s = arg_str(&a, "grid-ok", NULL)) != NULL && read_oracle(s, &oracle) < 0)
            goto done;
        b.test = print_fn;
        b.ctx = &oracle;
        for (int k = 0; k < nipv; k++)
            for (int t = 0; t < BC_NTESTS; t++)
                if (tests[t])
                    bc_scripts(&b, t, "example.com", ipvs[k]);
        rc = EXIT_OK;
        goto done;
    }

    eval_opts_default(&o);
    o.runs = 1;
    o.skip_empty = 0;
    o.stop = &stop;
    if (arg_int(&a, "local-ports", 30000, 1024, 65535 - 64, &v) < 0)
        goto done;
    o.port_base = (uint16_t)v;
    if (arg_int(&a, "queue", 311, 0, 65535, &v) < 0)
        goto done;
    o.fw.queue = (uint16_t)v;
    if ((s = arg_str(&a, "mark", NULL)) != NULL) {
        char *end;
        unsigned long m = strtoul(s, &end, 0);
        if (*end || !m || m > 0xffffffffUL) {
            fprintf(stderr, "geneva blockcheck: bad --mark %s\n", s);
            goto done;
        }
        o.fw.mark = (uint32_t)m;
    }
    if ((s = arg_str(&a, "firewall", NULL)) != NULL && fw_backend_parse(s, &o.fw.backend) < 0) {
        fprintf(stderr, "geneva blockcheck: --firewall must be auto, nft or iptables\n");
        goto done;
    }
    stop_on_signals(&stop);
    res.curl = curl;
    res.timeout = timeout;
    if (!arg_has(&a, "skip-dnscheck")) {
        bc_dnscheck dc;
        double dto = timeout;
        dc.servers = dns_servers;
        dc.nservers = ndns_servers;
        dc.domains = dns_domains;
        dc.ndomains = ndns_domains;
        dc.lookup = bc_lookup;
        dc.ctx = &dto;
        dc.log = b.log;
        bc_check_dns(&dc, &b.dns);
    }
    if (b.dns.spoofed && secure < 0)
        secure = 1;
    if (secure == 1) {
        /* doh_find_working */
        if ((s = arg_str(&a, "doh", NULL)) != NULL) {
            snprintf(b.dns.doh, sizeof(b.dns.doh), "%s", s);
        } else {
            if (b.log)
                fprintf(b.log, "* searching working DoH server\n");
            for (int i = 0; i < ndohs && !b.dns.doh[0]; i++) {
                bc_ip ip[BC_MAXIP];
                sbuf err;
                sb_init(&err);
                if (bc_doh_query(curl, dohs[i], timeout, "iana.org", 4, ip, BC_MAXIP, &err) > 0)
                    snprintf(b.dns.doh, sizeof(b.dns.doh), "%s", dohs[i]);
                if (b.log)
                    fprintf(b.log, "%s : %s%s%s\n", dohs[i], b.dns.doh[0] ? "OK" : "FAIL", b.dns.doh[0] ? "" : ": ",
                            b.dns.doh[0] ? "" : err.data);
                sb_free(&err);
            }
            if (!b.dns.doh[0]) {
                fprintf(stderr, "geneva blockcheck: all DoH servers failed. could not find working DoH server. exiting.\n");
                rc = EXIT_FAIL;
                goto done;
            }
        }
        b.dns.secure = 1;
        res.doh = b.dns.doh;
    }
    b.test = test_fn;
    b.ctx = &cmd;
    rc = EXIT_OK;
    for (int d = 0; d < ndom && !stop; d++)
        for (int k = 0; k < nipv && !stop; k++)
            for (int t = 0; t < BC_NTESTS && !stop; t++) {
                char ip[64], cmdline[1024];
                bc_ip ips[BC_MAXIP];
                sbuf err;
                int base;
                if (!tests[t])
                    continue;
                b.testf = bc_test_name(t);
                b.ipv = ipvs[k];
                /* the main loop: port 80 before http, 443 before the first TLS test */
                if (!skip_ipblock && (t == BC_HTTP || t == BC_TLS12 || (t == BC_TLS13 && !tests[BC_TLS12])))
                    port_block(&b, &res, doms[d], fixed_ip, t == BC_HTTP ? 80 : 443);
                if (b.log)
                    fprintf(b.log, "\n* %s ipv%d %s\n", b.testf, b.ipv, doms[d]);
                if (fixed_ip)
                    snprintf(ip, sizeof(ip), "%s", fixed_ip);
                else if (bc_resolve_all(&res, doms[d], b.ipv, ips, BC_MAXIP) > 0)
                    snprintf(ip, sizeof(ip), "%s", ips[0]);
                else {
                    /* check_domain_prolog: curl's code 6 */
                    if (b.log)
                        fprintf(b.log, "%s does not resolve for ipv%d\n", doms[d], b.ipv);
                    bc_report(&b, doms[d], "test aborted, no reason to continue. curl code 6: could not resolve host",
                              NULL);
                    continue;
                }
                setup_probe(&o.probe, t, doms[d], ip, b.ipv, timeout, curl, cmdline, sizeof(cmdline));
                sb_init(&err);
                if (probe_resolve(&o.probe, &err) < 0) {
                    fprintf(stderr, "geneva blockcheck: %s\n", err.data);
                    sb_free(&err);
                    rc = EXIT_FAIL;
                    goto done;
                }
                base = evaluator_open(&o, &cmd.ev, &err);
                if (base != EXIT_OK) {
                    fprintf(stderr, "geneva blockcheck: %s\n", err.data);
                    sb_free(&err);
                    rc = base;
                    goto done;
                }
                sb_free(&err);
                /* check_domain_prolog: without a strategy */
                if (b.log)
                    fprintf(b.log, "- checking without DPI bypass\n");
                base = attempts(&cmd, NULL);
                if (base > 0) {
                    bc_report(&b, doms[d], "working without bypass", NULL);
                    found = 1;
                }
                if (base >= 0 && (base == 0 || b.level == BC_FORCE)) {
                    int r;
                    if (!skip_ipblock && t != BC_HTTP3)
                        ip_block(&b, &cmd, &res, t, doms[d], fixed_ip, unblocked, timeout);
                    r = bc_scripts(&b, t, doms[d], b.ipv);
                    if (r > 0)
                        found = 1;
                }
                evaluator_close(cmd.ev);
                cmd.ev = NULL;
            }
    if (stop) {
        rc = EXIT_FAIL;
        fprintf(stderr, "geneva blockcheck: stopped\n");
    }
    if (arg_has(&a, "json")) {
        sbuf j;
        sb_init(&j);
        bc_print_json(&b, ndom, &j);
        printf("%s\n", j.data);
        sb_free(&j);
    } else {
        bc_print(&b, ndom, stdout);
        if (b.level != BC_FORCE && ndom > 1)
            printf("Current scan level was \"%s\".\n", level_opt[b.level]);
    }
    if (rc == EXIT_OK && !found)
        rc = EXIT_FAIL;
done:
    evaluator_close(cmd.ev);
    for (size_t i = 0; i < oracle.n; i++)
        free(oracle.ok[i]);
    free(oracle.ok);
    for (int i = 0; i < ndom; i++)
        free(doms[i]);
    free(doms);
    free_list(dns_servers, ndns_servers);
    free_list(dns_domains, ndns_domains);
    free_list(dohs, ndohs);
    bc_resolver_free(&res);
    bc_free(&b);
    args_free(&a);
    return rc;
}
