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

/* the domain's first address of the IP version (mdig_resolve) */
static int resolve(const char *dom, int ipv, char *out, size_t cap)
{
    struct addrinfo hints, *res = NULL;
    int ok = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ipv == 6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(dom, NULL, &hints, &res) || !res)
        return -1;
    if (res->ai_family == AF_INET)
        ok = inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, out, (socklen_t)cap) != NULL;
    else if (res->ai_family == AF_INET6)
        ok = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr, out, (socklen_t)cap) != NULL;
    freeaddrinfo(res);
    return ok ? 0 : -1;
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
        {"curl", 0, 1, "PATH", "http3: the curl with HTTP/3 (default curl)"},
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
    args_t a;
    char aerr[128];
    int tests[BC_NTESTS] = {0}, rc = EXIT_USAGE, idx = 0, found = 0, print, ipvs[2], nipv = 0;
    int64_t v;
    double timeout;
    const char *s, *curl, *fixed_ip;
    char **doms = NULL;
    int ndom = 0;
    bc_run b;
    bc_cmd cmd;
    eval_opts o;
    grid_oracle oracle = {NULL, 0};

    bc_init(&b);
    memset(&cmd, 0, sizeof(cmd));
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
                  "and COVERAGE. Exit code 0 when something works, 1 otherwise.\n"
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
        if (strspn(doms[i], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_") != strlen(doms[i])) {
            /* the name goes into curl's command line (http3) and the Host header */
            fprintf(stderr, "geneva blockcheck: bad domain %s\n", doms[i]);
            goto done;
        }
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
    b.test = test_fn;
    b.ctx = &cmd;
    rc = EXIT_OK;
    for (int d = 0; d < ndom && !stop; d++)
        for (int k = 0; k < nipv && !stop; k++)
            for (int t = 0; t < BC_NTESTS && !stop; t++) {
                char ip[64], cmdline[1024];
                sbuf err;
                int base;
                if (!tests[t])
                    continue;
                b.testf = bc_test_name(t);
                b.ipv = ipvs[k];
                if (b.log)
                    fprintf(b.log, "\n* %s ipv%d %s\n", b.testf, b.ipv, doms[d]);
                if (fixed_ip)
                    snprintf(ip, sizeof(ip), "%s", fixed_ip);
                else if (resolve(doms[d], b.ipv, ip, sizeof(ip)) < 0) {
                    /* check_domain_prolog: curl's code 6 */
                    if (b.log)
                        fprintf(b.log, "%s does not resolve for ipv%d\n", doms[d], b.ipv);
                    bc_report(&b, doms[d], "test aborted, no reason to continue. curl code 6: could not resolve host",
                              NULL);
                    continue;
                }
                memset(&o.probe, 0, sizeof(o.probe));
                o.probe.host = doms[d];
                o.probe.ip = ip;
                o.probe.timeout = timeout;
                o.probe.path = "/";
                o.probe.max_bytes = 4u << 20;
                switch (t) {
                case BC_HTTP:
                    o.probe.kind = PROBE_HTTP;
                    o.probe.port = 80;
                    o.probe.strict_http = 1;
                    break;
                case BC_TLS12:
                case BC_TLS13:
                    o.probe.kind = PROBE_TLS;
                    o.probe.port = 443;
                    o.probe.tls_version = t == BC_TLS12 ? 12 : 13;
                    break;
                default:
                    o.probe.kind = PROBE_EXEC;
                    o.probe.port = 443;
                    snprintf(cmdline, sizeof(cmdline),
                             "%s --http3-only -Ss --max-time %g --local-port {lports} --connect-to %s::%s%s%s:443 "
                             "-o %s https://%s",
                             curl, timeout, doms[d], b.ipv == 6 ? "[" : "", ip, b.ipv == 6 ? "]" : "",
#ifdef _WIN32
                             "NUL",
#else
                             "/dev/null",
#endif
                             doms[d]);
                    o.probe.cmd = cmdline;
                    o.probe.timeout = timeout + 5;
                    break;
                }
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
                    int r = bc_scripts(&b, t, doms[d], b.ipv);
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
    bc_free(&b);
    args_free(&a);
    return rc;
}
