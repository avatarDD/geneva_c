/*
 * "geneva eval": evaluates strategies (or none: the baseline) against a
 * target with a probe, the way "geneva evolve" scores its individuals.
 */
#include "cmd_eval.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "log.h"
#include "plat.h"

/* ---- signals ------------------------------------------------------------- */

static volatile sig_atomic_t *g_flag;

#ifdef _WIN32
static BOOL WINAPI on_console(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        if (g_flag)
            *g_flag = 1;
        return TRUE;
    }
    return FALSE;
}
#else
static void on_signal(int sig)
{
    (void)sig;
    if (g_flag)
        *g_flag = 1;
}
#endif

void stop_on_signals(volatile sig_atomic_t *flag)
{
    g_flag = flag;
#ifdef _WIN32
    SetConsoleCtrlHandler(on_console, TRUE);
#else
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        signal(SIGPIPE, SIG_IGN);
    }
#endif
}

/* ---- options ------------------------------------------------------------- */

static int get_size(const args_t *a, const char *name, size_t def, size_t *out)
{
    int64_t v;
    if (arg_int(a, name, (int64_t)def, 0, INT64_C(1) << 40, &v) < 0)
        return -1;
    *out = (size_t)v;
    return 0;
}

int eval_parse_args(const args_t *a, const char *cmd, eval_opts *o)
{
    probe_cfg *c = &o->probe;
    const char *s;
    int64_t v;
    sbuf err;

    if ((s = arg_str(a, "probe", NULL)) != NULL && probe_kind_parse(s, &c->kind) < 0) {
        fprintf(stderr, "geneva %s: --probe must be http, tls, dns, tcp, exec or external\n", cmd);
        return -1;
    }
    c->host = arg_str(a, "host", NULL);
    c->ip = arg_str(a, "ip", NULL);
    switch (c->kind) {
    case PROBE_HTTP: v = 80; break;
    case PROBE_TLS: v = 443; break;
    case PROBE_DNS: v = 53; break;
    default: v = 0; break;
    }
    if (arg_int(a, "port", v, 0, 65535, &v) < 0)
        return -1;
    c->port = (uint16_t)v;
    c->path = arg_str(a, "path", "/");
    c->bad_word = arg_str(a, "bad-word", NULL);
    c->valid_contains = arg_str(a, "valid-contains", NULL);
    c->injected_contains = arg_str(a, "injected-contains", NULL);
    if (get_size(a, "min-bytes", 0, &c->min_bytes) < 0 || get_size(a, "max-bytes", 4u << 20, &c->max_bytes) < 0)
        return -1;
    if ((s = arg_str(a, "tls-version", NULL)) != NULL) {
        if (!strcmp(s, "1.2"))
            c->tls_version = 12;
        else if (!strcmp(s, "1.3"))
            c->tls_version = 13;
        else if (strcmp(s, "any")) {
            fprintf(stderr, "geneva %s: --tls-version must be 1.2, 1.3 or any\n", cmd);
            return -1;
        }
    }
    c->alpn = arg_str(a, "alpn", NULL);
    c->dns_tcp = arg_has(a, "dns-tcp");
    c->dns_aaaa = arg_has(a, "dns-aaaa");
    c->dns_expect = arg_str(a, "dns-expect", NULL);
    c->dns_bad = arg_str(a, "dns-bad", NULL);
    if ((s = arg_str(a, "payload", NULL)) != NULL && probe_parse_payload(s, &c->payload, &c->payload_len) < 0) {
        fprintf(stderr, "geneva %s: bad --payload (escapes: \\r \\n \\t \\0 \\\\ \\xHH, or hex:...)\n", cmd);
        return -1;
    }
    c->cmd = arg_str(a, "cmd", NULL);
    if (arg_dbl(a, "timeout", c->kind == PROBE_EXEC ? 20 : 5, 0.05, 3600, &c->timeout) < 0)
        return -1;

    if (arg_int(a, "runs", 1, 1, 64, &v) < 0)
        return -1;
    o->runs = (int)v;
    if ((s = arg_str(a, "fitness-by", NULL)) != NULL) {
        if (!strcmp(s, "avg"))
            o->by = FIT_AVG;
        else if (!strcmp(s, "min"))
            o->by = FIT_MIN;
        else if (!strcmp(s, "max"))
            o->by = FIT_MAX;
        else {
            fprintf(stderr, "geneva %s: --fitness-by must be avg, min or max\n", cmd);
            return -1;
        }
    }
    if (arg_int(a, "workers", 1, 1, EVAL_MAX_WORKERS, &v) < 0)
        return -1;
    o->workers = (int)v;
    if (arg_dbl(a, "residual-wait", 0, 0, 3600, &o->residual_wait) < 0)
        return -1;
    if (arg_int(a, "local-ports", 30000, 1024, 65535 - EVAL_MAX_WORKERS * 64, &v) < 0)
        return -1;
    o->port_base = (uint16_t)v;
    o->use_engine = !arg_has(a, "no-engine");
    if (arg_int(a, "queue", 311, 0, 65535, &v) < 0)
        return -1;
    o->fw.queue = (uint16_t)v;
    if ((s = arg_str(a, "mark", NULL)) != NULL) {
        char *end;
        unsigned long m = strtoul(s, &end, 0);
        if (*end || !m || m > 0xffffffffUL) {
            fprintf(stderr, "geneva %s: bad --mark %s\n", cmd, s);
            return -1;
        }
        o->fw.mark = (uint32_t)m;
    }
    if ((s = arg_str(a, "firewall", NULL)) != NULL && fw_backend_parse(s, &o->fw.backend) < 0) {
        fprintf(stderr, "geneva %s: --firewall must be auto, nft or iptables\n", cmd);
        return -1;
    }

    if (arg_has(a, "agent") && arg_has(a, "agent-listen")) {
        fprintf(stderr, "geneva %s: --agent and --agent-listen exclude each other\n", cmd);
        return -1;
    }
    o->agent = arg_str(a, "agent", NULL);
    if (!o->agent && (o->agent = arg_str(a, "agent-listen", NULL)) != NULL)
        o->agent_listen = 1;
    o->agent_token = arg_str(a, "agent-token", getenv("GENEVA_AGENT_TOKEN"));
    if (arg_dbl(a, "agent-wait", 300, 1, 86400, &o->agent_wait) < 0)
        return -1;
    if (o->agent) {
        if (c->kind == PROBE_EXEC || c->kind == PROBE_EXTERNAL) {
            fprintf(stderr, "geneva %s: the agent runs http, tls, dns and tcp probes\n", cmd);
            return -1;
        }
        if (o->workers > 1) {
            fprintf(stderr, "geneva %s: server-side evaluation runs one strategy at a time (--workers 1)\n", cmd);
            return -1;
        }
        if (!c->port) {
            fprintf(stderr, "geneva %s: server-side evaluation needs --port of the service\n", cmd);
            return -1;
        }
        /* the strategy applies to the service: its port is the one slot */
        o->port_base = c->port;
        o->ports_per_worker = 1;
    }

    switch (c->kind) {
    case PROBE_DNS:
        if (!c->host) {
            fprintf(stderr, "geneva %s: the dns probe needs --host NAME to query\n", cmd);
            return -1;
        }
        if (!c->ip)
            c->ip = "8.8.8.8";
        break;
    case PROBE_TCP:
        if (!c->port) {
            fprintf(stderr, "geneva %s: the tcp probe needs --port\n", cmd);
            return -1;
        }
        break;
    case PROBE_EXEC:
        if (!c->cmd) {
            fprintf(stderr, "geneva %s: the exec probe needs --cmd COMMAND\n", cmd);
            return -1;
        }
        break;
    case PROBE_EXTERNAL:
        if (!ev_enabled()) {
            fprintf(stderr, "geneva %s: the external probe sends its requests as events: add --events\n", cmd);
            return -1;
        }
        if (o->workers > 1) {
            fprintf(stderr, "geneva %s: the external probe runs one strategy at a time (--workers 1)\n", cmd);
            return -1;
        }
        o->ext_in = stdin;
        break;
    default:
        break;
    }
    if ((c->kind == PROBE_HTTP || c->kind == PROBE_TLS) && !c->host && !c->ip) {
        fprintf(stderr, "geneva %s: need --host (and optionally --ip)\n", cmd);
        return -1;
    }
    if (c->kind == PROBE_TCP && !c->host && !c->ip) {
        fprintf(stderr, "geneva %s: need --ip or --host\n", cmd);
        return -1;
    }
    sb_init(&err);
    if (probe_resolve(c, &err) < 0) {
        fprintf(stderr, "geneva %s: %s\n", cmd, err.data);
        sb_free(&err);
        return -1;
    }
    sb_free(&err);
    return 0;
}

void eval_target_name(const eval_opts *o, sbuf *out)
{
    const probe_cfg *c = &o->probe;
    sb_puts(out, probe_kind_name(c->kind));
    if (c->kind == PROBE_EXEC || c->kind == PROBE_EXTERNAL) {
        if (c->host)
            sb_printf(out, ":%s", c->host);
        return;
    }
    sb_printf(out, ":%s", c->host ? c->host : c->ip);
    if (c->kind == PROBE_DNS)
        sb_printf(out, "@%s%s", c->ip, c->dns_tcp ? "/tcp" : "");
    else
        sb_printf(out, ":%u", (unsigned)c->port);
}

/* ---- geneva eval --------------------------------------------------------- */

static void add_file(const char *path, char ***v, size_t *n, int *bad)
{
    size_t len;
    char *text, *line, *next;
    if (!strcmp(path, "-")) { /* geneva library -q ... | geneva eval -f - */
        sbuf in;
        char buf[4096];
        size_t got;
        sb_init(&in);
        while ((got = fread(buf, 1, sizeof(buf), stdin)) > 0)
            sb_append(&in, buf, got);
        text = sb_take(&in);
    } else {
        text = read_file(path, &len);
    }
    if (!text) {
        fprintf(stderr, "geneva eval: cannot read %s\n", path);
        *bad = 1;
        return;
    }
    for (line = text; line && *line; line = next) {
        char *p = line, *end;
        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        while (*p == ' ' || *p == '\t')
            p++;
        end = p + strlen(p);
        while (end > p && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
            *--end = 0;
        if (!*p || *p == '#')
            continue;
        *v = xrealloc(*v, (*n + 1) * sizeof(**v));
        (*v)[(*n)++] = xstrdup(p);
    }
    free(text);
}

int cmd_eval(int argc, char **argv)
{
    static const optdef defs[] = {
        {"strategy", 's', 1, "STRATEGY", "strategy to evaluate (repeatable)"},
        {"strategy-file", 'f', 1, "FILE", "strategies to evaluate, one per line (- for stdin)"},
        EVAL_OPTS,
        {"log-level", 'l', 1, "LEVEL", "error, warn, info (default), debug or trace"},
        {"log-format", 0, 1, "FMT", "text (default) or json"},
        {"log-file", 0, 1, "FILE", "also write the log to FILE"},
        {"verbose", 'v', 0, NULL, "same as --log-level trace"},
        {"quiet", 0, 0, NULL, "no log on stderr"},
        {"events", 'e', 1, "SINK", "JSON Lines events: - (stdout), stderr, FILE or none"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    static volatile sig_atomic_t stop;
    args_t a;
    char aerr[128];
    eval_opts o;
    evaluator *ev = NULL;
    char **strats = NULL;
    size_t ns = 0;
    int rc = EXIT_USAGE, bad = 0, any_ok = 0, idx = 0;
    const char *s;
    sbuf err;

    if (args_parse(&a, argc, argv, defs, aerr, sizeof(aerr)) < 0) {
        fprintf(stderr, "geneva eval: %s\n", aerr);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva eval [options] [-s STRATEGY]... [-f FILE] [STRATEGY...]\n"
                  "Runs the probe through each strategy and prints \"fitness<TAB>strategy\".\n"
                  "Without strategies, runs the probe without one (the baseline).\n"
                  "Exit code 0 when some strategy (or the baseline) succeeded, 1 otherwise.\n"
                  "Needs root (Administrator) for the engine, except with --no-engine.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    sb_init(&err);
    eval_opts_default(&o);
    if (parse_logging(&a, "eval") < 0 || eval_parse_args(&a, "eval", &o) < 0)
        goto done;
    while ((s = arg_next(&a, "strategy", &idx)) != NULL) {
        strats = xrealloc(strats, (ns + 1) * sizeof(*strats));
        strats[ns++] = xstrdup(s);
    }
    idx = 0;
    while ((s = arg_next(&a, "strategy-file", &idx)) != NULL) {
        if (!strcmp(s, "-") && o.probe.kind == PROBE_EXTERNAL) {
            fprintf(stderr, "geneva eval: the external probe reads its results from stdin: no -f -\n");
            goto done;
        }
        add_file(s, &strats, &ns, &bad);
    }
    for (int i = 0; i < a.npos; i++) {
        strats = xrealloc(strats, (ns + 1) * sizeof(*strats));
        strats[ns++] = xstrdup(a.pos[i]);
    }
    if (bad)
        goto done;
    for (size_t i = 0; i < ns; i++) {
        strategy *st = strategy_parse(strats[i], &err);
        if (!st) {
            fprintf(stderr, "geneva eval: %s: %s\n", strats[i], err.data);
            rc = EXIT_STRATEGY;
            goto done;
        }
        if (strategy_len(st) && !o.use_engine) {
            fprintf(stderr, "geneva eval: strategies need the engine (drop --no-engine)\n");
            strategy_free(st);
            goto done;
        }
        strategy_free(st);
    }
    if (!ns)
        o.use_engine = 0; /* the baseline needs no engine */
    o.skip_empty = 0;
    o.stop = &stop;
    stop_on_signals(&stop);
    rc = evaluator_open(&o, &ev, &err);
    if (rc != EXIT_OK) {
        fprintf(stderr, "geneva eval: %s\n", err.data);
        goto done;
    }
    if (!ns) {
        eval_result r;
        int reachable = 0;
        if (evaluator_baseline(ev, &r, &reachable, NULL, NULL) < 0) {
            rc = EXIT_FAIL;
            goto done;
        }
        LOGI("eval", "baseline: %s (%s)", probe_outcome_name(r.last.outcome), r.last.detail);
        printf("%g\t%s\n", r.fitness, "(no strategy)");
        any_ok = reachable;
    } else if (o.workers > 1 && ns > 1) {
        ga_ind *inds = xcalloc(ns, sizeof(*inds));
        for (size_t i = 0; i < ns; i++) {
            inds[i].s = strategy_parse(strats[i], &err);
            inds[i].str = strats[i];
        }
        rc = evaluator_ga(ev, inds, ns) < 0 ? EXIT_FAIL : EXIT_OK;
        for (size_t i = 0; i < ns; i++) {
            printf("%g\t%s\n", inds[i].fit, strats[i]);
            any_ok |= inds[i].fit > 0;
            strategy_free(inds[i].s);
        }
        free(inds);
        if (rc != EXIT_OK)
            goto done;
    } else {
        for (size_t i = 0; i < ns; i++) {
            eval_result r;
            if (evaluator_eval(ev, strats[i], &r) < 0) {
                rc = EXIT_FAIL;
                goto done;
            }
            LOGI("eval", "Fitness %g: %s (%s: %s)", r.fitness, strats[i], probe_outcome_name(r.last.outcome),
                 r.last.detail);
            printf("%g\t%s\n", r.fitness, strats[i]);
            fflush(stdout);
            any_ok |= r.fitness > 0;
        }
    }
    rc = any_ok ? EXIT_OK : EXIT_FAIL;
done:
    evaluator_close(ev);
    for (size_t i = 0; i < ns; i++)
        free(strats[i]);
    free(strats);
    free(o.probe.payload);
    sb_free(&err);
    args_free(&a);
    return rc;
}
