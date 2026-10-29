/*
 * "geneva run": the strategy engine.
 * "geneva fw":  print, apply or remove its firewall rules by hand.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine.h"
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
    {"first", 0, 1, "N", "intercept only the first N packets of each connection (needs conntrack)"}, \
    {"prenat", 0, 0, NULL, "nft: intercept outgoing packets before SNAT (default after)"},         \
    {"no-notrack", 0, 0, NULL, "leave packets the engine sends in conntrack"},                     \
    {"no-bypass", 0, 0, NULL, "drop instead of pass traffic while no engine listens"},            \
    {"forward-to", 0, 1, "ADDR", "Geneva forwarder: DNAT the ports to ADDR and masquerade"}

/* Fills the firewall part of the configuration. Returns 0 or prints an
 * error and returns -1. */
static int parse_fw(const args_t *a, const char *cmd, fw_config *c, int *use_fw)
{
    int64_t v;
    const char *s;
    *use_fw = 1;
    if (!arg_has(a, "server-port") || ports_parse(arg_str(a, "server-port", ""), &c->ports) < 0) {
        fprintf(stderr, "geneva %s: need --server-port PORTS (like 443 or 80,443 or 8000-8100)\n", cmd);
        return -1;
    }
    c->server_side = arg_has(a, "server-side");
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
    if (arg_int(a, "queue", 310, 0, 65535, &v) < 0)
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
    /* WinDivert captures by a filter: the Linux-only rule options mean nothing */
    if (c->first || c->forward_to || c->prenat || !*use_fw || c->backend != FW_AUTO) {
        fprintf(stderr, "geneva %s: --first, --forward-to, --prenat and --firewall are Linux-only\n", cmd);
        return -1;
    }
#endif
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
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    engine_opts o;
    int64_t v;
    int rc;

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
    if (a.npos) {
        fprintf(stderr, "geneva run: unexpected argument \"%s\"\n", a.pos[0]);
        goto done;
    }
    o.strategy = arg_str(&a, "strategy", NULL);
    o.strategy_file = arg_str(&a, "strategy-file", NULL);
    if (!!o.strategy == !!o.strategy_file) {
        fprintf(stderr, "geneva run: give exactly one of --strategy and --strategy-file\n");
        goto done;
    }
    if (parse_fw(&a, "run", &o.fw, &o.apply_fw) < 0 || parse_logging(&a, "run") < 0)
        goto done;
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
    rc = engine_run(&o);
done:
    args_free(&a);
    return rc;
}

int cmd_fw(int argc, char **argv)
{
    static const optdef defs[] = {
        FW_OPTS,
        {"log-level", 'l', 1, "LEVEL", "debug shows every command"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    fw_config c;
    int use_fw, rc = EXIT_USAGE;
    const char *act;

    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva fw: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva fw print|up|down -p PORTS [options]\n"
                  "Prints, applies or removes the rules \"geneva run\" uses. Give the same\n"
                  "options as to \"geneva run\"; then run it with --firewall none.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    fw_config_default(&c);
    if (a.npos != 1) {
        fprintf(stderr, "geneva fw: need one action: print, up or down\n");
        goto done;
    }
    act = a.pos[0];
    if (parse_fw(&a, "fw", &c, &use_fw) < 0 || parse_logging(&a, "fw") < 0)
        goto done;
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
    args_free(&a);
    return rc;
}
