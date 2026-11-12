/*
 * "geneva run": the strategy engine.
 * "geneva fw":  print, apply or remove its firewall rules by hand.
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#if GENEVA_EXT
#  include "ext/auto.h"
#  include "ext/ext.h"
#  include "ext/fwx.h"
#  include "ext/svc.h"
#endif
#include "engine.h"
#include "evaluator.h"
#include "fw.h"
#include "geneva.h"
#include "log.h"
#include "rng.h"
#include "plat.h"
#include "util.h"

#define FW_OPTS                                                                                   \
    {"server-port", 'p', 1, "PORTS", "ports of the service: 443 or 80,443 or 8000-8100 (required)"}, \
    {"server-side", 0, 0, NULL, "run on the server: outbound packets come from PORTS"},          \
    {"proto", 0, 1, "LIST", "tcp, udp or tcp,udp (default tcp)"},                                \
    {"queue", 'q', 1, "N", "NFQUEUE number (default 310)"},                                      \
    {"mark", 0, 1, "MASK", "fwmark bit of packets the engine sends itself (default 0x20000000)"}, \
    {"firewall", 0, 1, "TYPE", "auto, nft, iptables, or none (rules set up by hand)"},             \
    {"iface", 'i', 1, "IF", "only traffic through this interface (the WAN on a router)"},         \
    {"dir", 0, 1, "both|out|in", "directions to intercept (default both)"},                       \
    {"ipv4-only", '4', 0, NULL, "handle IPv4 only"},                                               \
    {"ipv6-only", '6', 0, NULL, "handle IPv6 only"},                                               \
    {"first", 0, 1, "N", "apply the strategy to the first N packets of each connection per direction"}, \
    {"prenat", 0, 0, NULL, "nft: intercept outgoing packets before SNAT (default after)"},         \
    {"no-notrack", 0, 0, NULL, "leave packets the engine sends in conntrack"},                     \
    {"no-bypass", 0, 0, NULL, "drop instead of pass traffic while no engine listens"},            \
    {"forward-to", 0, 1, "ADDR", "Geneva forwarder: DNAT the ports to ADDR and masquerade"},     \
    {"filter", 0, 1, "EXPR", "Windows: WinDivert filter to capture, replaces the one from -p/--proto/--dir"}, \
    {"filter-file", 0, 1, "FILE", "Windows: read the --filter expression from FILE (up to 64 KB)"}, \
    {"priority", 0, 1, "N", "Windows: WinDivert handle priority, -30000..30000 (default 0)"}

#if GENEVA_EXT
/* --ext --wf-save FILE: the filter is written, the command is done */
static int wf_save(const char *cmd, const char *path, const char *filter)
{
    FILE *f = fopen(path, "wb");
    int bad = !f || fputs(filter, f) < 0;
    if (f && fclose(f))
        bad = 1;
    if (bad) {
        fprintf(stderr, "geneva %s: cannot write %s\n", cmd, path);
        return -1;
    }
    return 1;
}
#endif

/* Fills the firewall part of the configuration. Returns 0, 1 when the
 * command is done (--ext --wf-save), or prints an error and returns -1. The
 * expression of a --filter-file (or of the --wf-* options) goes to *owned.
 * With eval (geneva fw for the evaluator) the ports come from elsewhere. */
static int parse_fw(const args_t *a, const char *cmd, fw_config *c, int *use_fw, char **owned, int eval)
{
    int64_t v;
    const char *s;
    sbuf ferr;
    *use_fw = 1;
    *owned = NULL;
    if (eval) {
        /* only what geneva eval/evolve themselves use */
        static const char *const run_only[] = {"server-port", "server-side", "iface", "dir", "ipv4-only",
                                               "ipv6-only", "first", "prenat", "no-notrack", "no-bypass",
                                               "forward-to"};
        for (size_t i = 0; i < ARRAY_LEN(run_only); i++)
            if (arg_has(a, run_only[i])) {
                fprintf(stderr, "geneva %s: --local-ports/--workers print the evaluator's rules, which have no --%s\n",
                        cmd, run_only[i]);
                return -1;
            }
        /* nor the --ext rules' (EXT_FW_OPTS) */
        for (int i = 0; i < a->nopts; i++) {
            static const char *const ext_fw[] = {"ext-first", "ext-wan", "ext-lan", "ext-notrack", "ext-ttl-icmp",
                                                 "ext-flowoffload"};
            const char *n = a->opts[i].def->name;
            int bad = !strncmp(n, "wf-", 3) || !strncmp(n, "fw-hook-", 8);
            for (size_t k = 0; k < ARRAY_LEN(ext_fw) && !bad; k++)
                bad = !strcmp(n, ext_fw[k]);
            if (bad) {
                fprintf(stderr, "geneva %s: --local-ports/--workers print the evaluator's rules, which have no --%s\n",
                        cmd, n);
                return -1;
            }
        }
    } else if (arg_has(a, "server-port")) {
        if (ports_parse(arg_str(a, "server-port", ""), &c->ports) < 0) {
            fprintf(stderr, "geneva %s: bad --server-port (like 443 or 80,443 or 8000-8100)\n", cmd);
            return -1;
        }
#if GENEVA_EXT
    } else if (ext_profiles()) {
        /* the ports of the profiles' --filter-tcp/--filter-udp, below */
    } else if (ext_enabled() && (xfw_wf_captures(a) || arg_has(a, "wf-save"))) {
        /* the --wf-* filter captures: WinDivert tells the direction */
#endif
    } else {
        fprintf(stderr, "geneva %s: need --server-port PORTS (like 443 or 80,443 or 8000-8100)\n", cmd);
        return -1;
    }
    c->server_side = arg_has(a, "server-side");
#if GENEVA_EXT
    if (!eval && ext_profiles()) {
        /* what the profiles take: ICMP, IP protocols, without -p the ports */
        sbuf perr;
        int r;
        sb_init(&perr);
        r = ext_profile_capture(c, !arg_has(a, "server-port"), &perr);
        if (r < 0)
            fprintf(stderr, "geneva %s: %s\n", cmd, perr.data);
        sb_free(&perr);
        if (r < 0)
            return -1;
    }
#endif
    if ((s = arg_str(a, "proto", NULL)) != NULL) {
        c->tcp = c->udp = 0;
        if (!strcmp(s, "tcp"))
            c->tcp = 1;
        else if (!strcmp(s, "udp"))
            c->udp = 1;
        else if (!strcmp(s, "tcp,udp") || !strcmp(s, "udp,tcp") || !strcmp(s, "all"))
            c->tcp = c->udp = 1;
        else {
            fprintf(stderr, "geneva %s: --proto must be tcp, udp or tcp,udp\n", cmd);
            return -1;
        }
    }
    if (arg_int(a, "queue", eval ? 311 : 310, 0, 65535, &v) < 0)
        return -1;
    c->queue = (uint16_t)v;
    if ((s = arg_str(a, "mark", NULL)) != NULL) {
        char *end;
        unsigned long m = strtoul(s, &end, 0);
        if (*end || !m || m > 0xffffffffUL) {
            fprintf(stderr, "geneva %s: bad --mark %s\n", cmd, s);
            return -1;
        }
        c->mark = (uint32_t)m;
    }
    if ((s = arg_str(a, "firewall", NULL)) != NULL) {
        if (!strcmp(s, "none"))
            *use_fw = 0;
        else if (fw_backend_parse(s, &c->backend) < 0) {
            fprintf(stderr, "geneva %s: --firewall must be auto, nft, iptables or none\n", cmd);
            return -1;
        }
    }
    c->iface = arg_str(a, "iface", NULL);
    if (c->iface && (strlen(c->iface) >= 16 || strpbrk(c->iface, " \t\"'\\;"))) {
        fprintf(stderr, "geneva %s: bad interface name\n", cmd);
        return -1;
    }
    if ((s = arg_str(a, "dir", NULL)) != NULL) {
        c->out = !strcmp(s, "both") || !strcmp(s, "out");
        c->in = !strcmp(s, "both") || !strcmp(s, "in");
        if (!c->out && !c->in) {
            fprintf(stderr, "geneva %s: --dir must be both, out or in\n", cmd);
            return -1;
        }
    }
    if (arg_has(a, "ipv4-only") && arg_has(a, "ipv6-only")) {
        fprintf(stderr, "geneva %s: --ipv4-only and --ipv6-only exclude each other\n", cmd);
        return -1;
    }
    if (arg_has(a, "ipv4-only"))
        c->ipv6 = 0;
    if (arg_has(a, "ipv6-only"))
        c->ipv4 = 0;
    if (arg_int(a, "first", 0, 0, 1000000, &v) < 0)
        return -1;
    c->first = (int)v;
    c->prenat = arg_has(a, "prenat");
    c->notrack = !arg_has(a, "no-notrack");
    c->bypass = !arg_has(a, "no-bypass");
    if ((s = arg_str(a, "forward-to", NULL)) != NULL) {
        uint8_t buf[16];
        if (inet_pton(strchr(s, ':') ? AF_INET6 : AF_INET, s, buf) != 1) {
            fprintf(stderr, "geneva %s: --forward-to needs an IP address\n", cmd);
            return -1;
        }
        c->forward_to = s;
    }
#ifdef _WIN32
    /* WinDivert captures by a filter: the Linux-only rule options mean
     * nothing (--first is counted by the engine itself there) */
    if (c->forward_to || c->prenat || !*use_fw || c->backend != FW_AUTO) {
        fprintf(stderr, "geneva %s: --forward-to, --prenat and --firewall are Linux-only\n", cmd);
        return -1;
    }
#endif
    sb_init(&ferr);
    if (fw_parse_filter_args(a, FW_WINDOWS, c, owned, &ferr) < 0) {
        fprintf(stderr, "geneva %s: %s\n", cmd, ferr.data);
        sb_free(&ferr);
        return -1;
    }
#if GENEVA_EXT
    if (ext_enabled() && !eval) {
        const char *save = NULL;
        if (xfw_parse(a, FW_WINDOWS, c, owned, &save, &ferr) < 0) {
            fprintf(stderr, "geneva %s: %s\n", cmd, ferr.data);
            sb_free(&ferr);
            return -1;
        }
        sb_free(&ferr);
        if (save)
            return wf_save(cmd, save, c->filter);
        if (c->offload && !*use_fw) {
            fprintf(stderr, "geneva %s: --ext-flowoffload makes rules: not with --firewall none\n", cmd);
            return -1;
        }
        return 0;
    }
#endif
    sb_free(&ferr);
    return 0;
}

int parse_logging(const args_t *a, const char *cmd)
{
    const char *s;
    log_level lvl;
    if ((s = arg_str(a, "log-level", NULL)) != NULL) {
        if (log_parse_level(s, &lvl) < 0) {
            fprintf(stderr, "geneva %s: bad --log-level %s\n", cmd, s);
            return -1;
        }
        log_set_level(lvl);
    }
    if (arg_has(a, "verbose"))
        log_set_level(LOG_TRACE);
    if ((s = arg_str(a, "log-format", NULL)) != NULL) {
        if (!strcmp(s, "json"))
            log_set_format(LOG_FMT_JSON);
        else if (strcmp(s, "text")) {
            fprintf(stderr, "geneva %s: --log-format must be text or json\n", cmd);
            return -1;
        }
    }
    if ((s = arg_str(a, "log-file", NULL)) != NULL && log_open_file(s) < 0) {
        fprintf(stderr, "geneva %s: cannot open %s\n", cmd, s);
        return -1;
    }
    if (arg_has(a, "quiet"))
        log_set_quiet(1);
    if ((s = arg_str(a, "events", NULL)) != NULL && ev_open(s) < 0) {
        fprintf(stderr, "geneva %s: cannot open event sink %s\n", cmd, s);
        return -1;
    }
    return 0;
}

#if GENEVA_EXT
/* --ext as a service (src/ext/svc.c): privileges go once packets flow */
typedef struct {
    xsvc *svc;
    const engine_opts *o;
} run_ready;

static void on_run_ready(void *ctx, int rc)
{
    run_ready *r = ctx;
    if (rc)
        return; /* the engine did not start */
    /* a failure comes before seccomp: the engine stops as on SIGTERM */
    if (xsvc_ready(r->svc, r->o->apply_fw ? &r->o->fw : NULL))
        raise(SIGTERM);
}

/* zapret2's marks (DESYNC_MARK, DESYNC_MARK_POSTNAT): our default is the
 * second (decision 11.5: warn only) */
static void warn_mark(uint32_t mark)
{
    if (mark & 0x20000000u)
        LOGW("run", "--mark 0x%x shares bit 0x20000000 with zapret2's DESYNC_MARK_POSTNAT: running nfqws2 on "
                    "this host too, give one of them another mark", (unsigned)mark);
    if (mark & 0x40000000u)
        LOGW("run", "--mark 0x%x shares bit 0x40000000 with zapret2's DESYNC_MARK: running nfqws2 on this host "
                    "too, give one of them another mark", (unsigned)mark);
}
#endif

int cmd_run(int argc, char **argv)
{
    static const optdef defs[] = {
        {"strategy", 's', 1, "STRATEGY", "strategy to run"},
        {"strategy-file", 'f', 1, "FILE", "read the strategy from FILE (re-read on SIGHUP)"},
        FW_OPTS,
        {"pcap", 0, 1, "FILE", "write the packets the engine releases to a pcap file"},
        {"control", 'c', 1, "ADDR", "control socket: unix:/path, tcp:PORT or tcp:HOST:PORT"},
        {"control-token", 0, 1, "TOKEN", "clients must send this token (or set GENEVA_CONTROL_TOKEN)"},
        {"events", 'e', 1, "SINK", "JSON Lines events: - (stdout), stderr, FILE or none"},
        {"stats-interval", 0, 1, "SEC", "emit a stats event every SEC seconds (default 10 with --events)"},
        {"duration", 0, 1, "SEC", "stop after SEC seconds"},
        {"queue-maxlen", 0, 1, "N", "packets the kernel may hold for us (default 4096)"},
        {"max-delayed", 0, 1, "N", "delayed packets (sleep) kept at once (default 1024)"},
        {"rng-seed", 0, 1, "N", "seed for random values (reproducible runs)"},
        {"log-level", 'l', 1, "LEVEL", "error, warn, info (default), debug or trace"},
        {"log-format", 0, 1, "FMT", "text (default) or json"},
        {"log-file", 0, 1, "FILE", "also write the log to FILE"},
        {"verbose", 'v', 0, NULL, "log every packet (same as --log-level trace)"},
        {"quiet", 0, 0, NULL, "no log on stderr"},
        EXT_OPT,
        EXT_CTRACK_OPTS,
        EXT_PROFILE_OPTS,
        EXT_FW_OPTS,
        EXT_RUN_OPTS,
        EXT_AUTO_OPTS,
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a, a0;
#if GENEVA_EXT
    xsvc svc;
    run_ready rr;
#endif
    char err[128];
    engine_opts o;
    char *filter_owned = NULL;
    int64_t v;
    int rc, r = 0;

    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva run: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva run -s STRATEGY -p PORTS [options]\n"
                  "Applies a strategy to live traffic: NFQUEUE on Linux (root), WinDivert on\n"
                  "Windows (Administrator, WinDivert.dll and WinDivert64.sys next to geneva.exe).\n"
                  "Signals: SIGHUP re-reads --strategy-file, SIGUSR1 emits stats,\n"
                  "SIGINT/SIGTERM stop and remove the firewall rules.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    engine_opts_default(&o);
    rc = EXIT_USAGE;
    if (ext_parse_args(&a, "run") < 0)
        goto done;
#if GENEVA_EXT
    o.ext = ext_engine_hooks();
#endif
    if (a.npos) {
        fprintf(stderr, "geneva run: unexpected argument \"%s\"\n", a.pos[0]);
        goto done;
    }
    a0 = ext_cmd_args(&a); /* the later -s/-f are other profiles' */
    o.strategy = arg_str(&a0, "strategy", NULL);
    o.strategy_file = arg_str(&a0, "strategy-file", NULL);
#if GENEVA_EXT
    if (!o.strategy && !o.strategy_file && ext_profiles())
        o.strategy = "\\/"; /* profiles only: the command's strategy does nothing */
#endif
    if (!!o.strategy == !!o.strategy_file) {
        fprintf(stderr, "geneva run: give exactly one of --strategy and --strategy-file\n");
        goto done;
    }
    if ((r = parse_fw(&a, "run", &o.fw, &o.apply_fw, &filter_owned, 0)) != 0 || parse_logging(&a, "run") < 0) {
        if (r > 0)
            rc = EXIT_OK; /* --wf-save */
        goto done;
    }
    if (!FW_WINDOWS && o.fw.filter_whole) {
        fprintf(stderr, "geneva run: the --wf-* filter is for WinDivert (Windows); --wf-save writes it anywhere\n");
        goto done;
    }
#if GENEVA_EXT
    if (ext_profiles()) {
        sbuf l;
        sb_init(&l);
        ext_profile_list(&l);
        LOGI("profile", "%zu profile(s): %s", ext_profiles(), l.data);
        sb_free(&l);
    }
#endif
    o.pcap = arg_str(&a, "pcap", NULL);
    o.control = arg_str(&a, "control", NULL);
    o.control_token = arg_str(&a, "control-token", getenv("GENEVA_CONTROL_TOKEN"));
    if (arg_dbl(&a, "stats-interval", ev_enabled() || o.control ? 10 : 0, 0, 86400, &o.stats_interval) < 0 ||
        arg_dbl(&a, "duration", 0, 0, 1e9, &o.duration) < 0)
        goto done;
    if (arg_int(&a, "queue-maxlen", 4096, 1, 1 << 20, &v) < 0)
        goto done;
    o.queue_maxlen = (uint32_t)v;
    if (arg_int(&a, "max-delayed", 1024, 1, 1 << 20, &v) < 0)
        goto done;
    o.max_delayed = (int)v;
    if (arg_int(&a, "rng-seed", 0, 0, INT64_MAX, &v) < 0)
        goto done;
    if (v)
        rng_global_seed((uint64_t)v);
#if GENEVA_EXT
    if (ext_enabled()) {
        sbuf e;
        sb_init(&e);
        r = xsvc_parse(&a, &svc, &e);
        if (r >= 0)
            r = xauto_parse(&a, &o.fw, &e);
        if (r >= 0 && (r = xsvc_workers(&a, o.fw.queue, FW_WINDOWS, plat_ncpu(), &o.workers, &e)) >= 0)
            o.fw.nqueues = (uint16_t)o.workers;
        if (r < 0 && e.len) /* arg_int printed its own */
            fprintf(stderr, "geneva run: %s\n", e.data);
        sb_free(&e);
        if (r < 0)
            goto done;
        warn_mark(o.fw.mark);
        if (svc.dry_run) {
            sb_init(&e);
            r = engine_check(&o, &e);
            if (r < 0)
                fprintf(stderr, "geneva run: %s\n", e.data);
            else
                printf("geneva run: the options are fine\n");
            sb_free(&e);
            rc = r < 0 ? EXIT_STRATEGY : EXIT_OK;
            goto done;
        }
        sb_init(&e);
        r = xsvc_start(&svc, &e);
        if (r >= 0) {
            /* the daemon's parent, or a failed start */
            if (e.len)
                fprintf(stderr, "geneva run: %s\n", e.data);
            sb_free(&e);
            rc = r;
            goto done;
        }
        sb_free(&e);
        rr.svc = &svc;
        rr.o = &o;
        o.on_ready = on_run_ready;
        o.ready_ctx = &rr;
        rc = engine_run(&o);
        xsvc_stop(&svc);
        if (svc.fail)
            rc = svc.fail;
        goto done;
    }
#endif
    rc = engine_run(&o);
done:
    free(filter_owned);
    args_free(&a);
    return rc;
}

int cmd_fw(int argc, char **argv)
{
    static const optdef defs[] = {
        FW_OPTS,
        {"local-ports", 0, 1, "BASE", "the evaluator's rules (eval/evolve --firewall none): ports from BASE"},
        {"workers", 0, 1, "N", "with --local-ports: the evaluator's workers, 64 ports each (default 1)"},
        {"probe", 0, 1, "KIND", "with --local-ports: dns, exec and external probes add UDP"},
        {"log-level", 'l', 1, "LEVEL", "debug shows every command"},
        EXT_OPT,
        EXT_PROFILE_OPTS,
        EXT_FW_OPTS,
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    fw_config c;
    int use_fw, rc = EXIT_USAGE, eval, r;
    const char *act;
    char *filter_owned = NULL;

    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva fw: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva fw print|up|down -p PORTS [options]\n"
                  "       geneva fw print|up|down --local-ports BASE [--workers N] [-q N] [--probe KIND]\n"
                  "Prints, applies or removes the rules \"geneva run\" uses. Give the same\n"
                  "options as to \"geneva run\"; then run it with --firewall none. With\n"
                  "--local-ports or --workers: the rules of \"geneva eval/evolve\" for its\n"
                  "worker slots (then run those with --firewall none and the same options).\n"
                  "On Windows \"print\" shows the WinDivert filter, --filter included.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (ext_parse_args(&a, "fw") < 0)
        goto done;
    fw_config_default(&c);
    if (a.npos != 1) {
        fprintf(stderr, "geneva fw: need one action: print, up or down\n");
        goto done;
    }
    act = a.pos[0];
    eval = arg_has(&a, "local-ports") || arg_has(&a, "workers") || arg_has(&a, "probe");
    if ((r = parse_fw(&a, "fw", &c, &use_fw, &filter_owned, eval)) != 0 || parse_logging(&a, "fw") < 0) {
        if (r > 0)
            rc = EXIT_OK; /* --wf-save */
        goto done;
    }
    if (eval) {
        /* the evaluator's engine: geneva eval/evolve's defaults */
        int64_t base, workers;
        probe_kind k = PROBE_HTTP;
        const char *ps = arg_str(&a, "probe", NULL);
        if (arg_int(&a, "local-ports", 30000, 1024, 65535 - EVAL_MAX_WORKERS * 64, &base) < 0 ||
            arg_int(&a, "workers", 1, 1, EVAL_MAX_WORKERS, &workers) < 0)
            goto done;
        if (ps && probe_kind_parse(ps, &k) < 0) {
            fprintf(stderr, "geneva fw: --probe must be http, tls, dns, tcp, exec or external\n");
            goto done;
        }
        fw_eval_slots(&c, (uint16_t)base, (uint32_t)(workers * 64), eval_needs_udp(k) || c.udp);
        c.filter_narrow = 1;
    }
#ifdef _WIN32
    if (!strcmp(act, "print")) {
        sbuf s, e;
        sb_init(&s);
        sb_init(&e);
        if (fw_windivert_filter(&c, &s, &e) < 0) {
            fprintf(stderr, "geneva fw: %s\n", e.data);
        } else {
            printf("# WinDivert filter (no firewall rules are needed on Windows)\n%s\n", s.data);
            rc = EXIT_OK;
        }
        sb_free(&s);
        sb_free(&e);
    } else {
        fprintf(stderr, "geneva fw: on Windows there are no rules to apply; only \"print\" works\n");
    }
    goto done;
#endif
    if (c.filter_whole) {
        /* --ext --wf-*: the WinDivert filter, shown on any platform */
        if (strcmp(act, "print")) {
            fprintf(stderr, "geneva fw: the --wf-* filter is for WinDivert (Windows); only \"print\" works\n");
            goto done;
        }
        printf("# WinDivert filter\n%s\n", c.filter);
        rc = EXIT_OK;
        goto done;
    }
    if (!strcmp(act, "print")) {
        sbuf s;
        fw_backend b = c.backend == FW_AUTO ? FW_NFT : c.backend;
        sb_init(&s);
        sb_printf(&s, "# %s: apply\n", fw_backend_name(b));
        fw_script(&c, b, 1, &s);
        sb_printf(&s, "# %s: remove\n", fw_backend_name(b));
        fw_script(&c, b, 0, &s);
        if (c.backend == FW_AUTO) {
            sb_puts(&s, "# iptables: apply\n");
            fw_script(&c, FW_IPTABLES, 1, &s);
            sb_puts(&s, "# iptables: remove\n");
            fw_script(&c, FW_IPTABLES, 0, &s);
        }
        fputs(s.data, stdout);
        sb_free(&s);
        rc = EXIT_OK;
    } else if (!strcmp(act, "up")) {
        sbuf e;
        sb_init(&e);
        if (fw_up(&c, &e) < 0) {
            fprintf(stderr, "geneva fw: %s\n", e.data);
            rc = EXIT_FIREWALL;
        } else {
            printf("%s\n", fw_backend_name(c.backend));
            rc = EXIT_OK;
        }
        sb_free(&e);
    } else if (!strcmp(act, "down")) {
        fw_down(&c);
        rc = EXIT_OK;
    } else {
        fprintf(stderr, "geneva fw: unknown action \"%s\" (print, up or down)\n", act);
    }
done:
    free(filter_owned);
    args_free(&a);
    return rc;
}
