/*
 * geneva — C port of Geneva (Genetic Evasion).
 * Multi-call binary: "geneva <command> [options]".
 */
#include <stdio.h>
#include <string.h>
#ifndef _WIN32
#  include <signal.h>
#endif

#include "args.h"
#include "ext_opt.h"
#if GENEVA_EXT
#  include "ext/cfgfile.h"
#  include "ext/ext.h"
#  include "ext/selftest.h"
#endif
#include "geneva.h"
#include "json.h"
#include "log.h"
#include "plat.h"
#include "util.h"

typedef struct {
    const char *name;
    int (*fn)(int argc, char **argv);
    const char *summary;
} command;

static const command commands[] = {
    {"agent", cmd_agent, "run the probes of a server-side evaluation (no root)"},
    {"apply", cmd_apply, "run a strategy over a pcap file offline"},
    {"censor", cmd_censor, "run one of Geneva's lab censors on a Linux router"},
    {"check", cmd_check, "parse, validate and print strategies"},
    {"ctl", cmd_ctl, "talk to a running engine over its control socket"},
    {"db", cmd_db, "list, rank, export and prune the strategy database"},
    {"eval", cmd_eval, "evaluate strategies against a target with a probe"},
    {"evolve", cmd_evolve, "search for strategies with the genetic algorithm"},
    {"fw", cmd_fw, "print, apply or remove the firewall rules of run"},
    {"library", cmd_library, "list the built-in strategies of Geneva's library"},
    {"run", cmd_run, "apply a strategy to live traffic (NFQUEUE or WinDivert)"},
    {"version", cmd_version, "print version and build features"},
};

static void usage(FILE *f)
{
    fprintf(f, "geneva %s - genetic censorship evasion (C port of Geneva)\n\n"
               "Usage: geneva <command> [options]\n\nCommands:\n",
            GENEVA_VERSION);
    for (size_t i = 0; i < ARRAY_LEN(commands); i++)
        fprintf(f, "  %-10s %s\n", commands[i].name, commands[i].summary);
    fprintf(f, "\nRun \"geneva <command> --help\" for command options.\n");
#if GENEVA_EXT
    fprintf(f, "\nExtensions (with --ext):\n"
               "  --ext after a command turns on the extensions beyond Geneva:\n"
               "  censor models 12-20 (geneva censor --ext --list); triggers FLOW:,\n"
               "  META: and L7: ([L7:host:example.com]-drop-|); x-actions after zapret2's\n"
               "  functions, NAME{key=value;...}: xfake xsplit xdisorder xtcpseg xhostfake\n"
               "  xfakedsplit xfakeddisorder xsend xmod; xsyndata xrst xsynack xsynacksplit\n"
               "  xwsize xwssize; xhttp{domcase;hostcase=hoSt;methodeol;unixeol}; xudplen\n"
               "  xdhtdn; xtlsclone (a changed copy of the ClientHello as a blob for the\n"
               "  actions after it); xtag (an own payload label); xlog (event ext_pkt);\n"
               "  xpcap{file=...}; combinators after zapret2's orchestrators:\n"
               "  xwhen{iff=COND;neg}(then,else), xstop{iff=COND}(rest),\n"
               "  xrepeat{repeats=N;iff=COND;stop}(body,rest), xcutoff{dir=in|out|both};\n"
               "  COND is cond_random (percent=P), cond_payload_str (pattern=TEXT),\n"
               "  cond_tcp_has_ts, cond_true, cond_false or a trigger such as FLOW:n:<5\n"
               "  or L7:payload:http_req, e.g.\n"
               "  [TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=3}(xdisorder{pos=1,midsld},)-| \\/\n"
               "  [TCP:flags:PA]-xtlsclone{blob=c;sni_first=a.example}(xfake{blob=c;ttl=3},)-| \\/\n"
               "  [TCP:flags:PA]-xwhen{iff=FLOW:n:<3}(xrepeat{repeats=2}(xfake{blob=0x41;ttl=1},),)-| \\/\n"
               "  xoob{urp=b|e|MARKER;char=C|byte=N} (an urgent byte) and xtlsrec{pos=MARKER}\n"
               "  (the TLS record cut in two) make the first message longer: they must see\n"
               "  the flow from its SYN, whose seq they shift, and incoming packets must\n"
               "  reach the queue until the server acks the message (its acks are mapped\n"
               "  back, its retransmissions sent again changed); xdrip{n=N;delay=MS} sends\n"
               "  the first N bytes one per segment with pauses, e.g.\n"
               "  [FLOW:n:1-]-xoob{urp=e}-| \\/   [FLOW:n:1-]-xtlsrec{pos=sniext+1}-| \\/\n"
               "  geneva CMD @FILE takes the options from FILE (with --ext); run --ext also\n"
               "  has --dry-run, --daemon, --pidfile, --user/--uid, seccomp and syslog.\n"
               "  geneva selftest --ext --fuzz N runs every reader of packets, captures,\n"
               "  strategies, lists and profiles over N random inputs (selftest --help).\n"
               "  See docs/EXT.md.\n");
#endif
}

int cmd_version(int argc, char **argv)
{
    static const optdef defs[] = {
        {"json", 0, 0, NULL, "machine-readable output"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva version: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva version [--json]", defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (arg_has(&a, "json")) {
        sbuf sb;
        jw w;
        sb_init(&sb);
        jw_init(&w, &sb);
        jw_obj(&w);
        jw_kstr(&w, "version", GENEVA_VERSION);
        jw_kint(&w, "proto", GENEVA_PROTO_VERSION);
        jw_kstr(&w, "os", plat_os_name());
        jw_kstr(&w, "arch", plat_arch_name());
        jw_key(&w, "features");
        jw_arr(&w);
#ifdef PLAT_LINUX
        jw_str(&w, "nfqueue");
#endif
#ifdef _WIN32
        jw_str(&w, "windivert");
#endif
        jw_str(&w, "ipv6");
        jw_str(&w, "pcap");
        jw_str(&w, "control");
        /* 1.1: integrators switch on these, not on version numbers */
#ifdef _WIN32
        jw_str(&w, "filter");     /* --filter, --filter-file, --priority */
        jw_str(&w, "set_filter"); /* set_filter, reload_filter, the "filter" event */
#endif
#if defined(PLAT_LINUX) || defined(_WIN32)
        jw_str(&w, "first");      /* --first N works here (Windows: counted by the engine) */
#endif
#ifdef PLAT_LINUX
        jw_str(&w, "firewall_none_eval"); /* eval/evolve --firewall none */
#endif
        jw_str(&w, "external_workers"); /* 1.2: --probe external with --workers N */
#if GENEVA_EXT
        for (const char *const *f = ext_features; *f; f++)
            jw_str(&w, *f); /* --ext and what it can do, last in the list */
#endif
        jw_arr_end(&w);
        jw_obj_end(&w);
        printf("%s\n", sb.data);
        sb_free(&sb);
    } else {
        printf("geneva %s (%s/%s)\n", GENEVA_VERSION, plat_os_name(), plat_arch_name());
    }
    args_free(&a);
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    const char *cmd;
#ifndef _WIN32
    /* Keenetic's service manager starts programs with SIGCHLD ignored, which
     * makes waitpid() lose the exit status of iptables, nft and exec probes;
     * we always reap our children ourselves. */
    signal(SIGCHLD, SIG_DFL);
#endif
    log_init();
    if (plat_net_init() < 0) {
        fprintf(stderr, "geneva: network initialization failed\n");
        return EXIT_FAIL;
    }
    if (argc < 2) {
        usage(stderr);
        return EXIT_USAGE;
    }
    cmd = argv[1];
    if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0 || strcmp(cmd, "help") == 0) {
        usage(stdout);
        return EXIT_OK;
    }
    if (strcmp(cmd, "-V") == 0 || strcmp(cmd, "--version") == 0)
        return cmd_version(0, NULL);
#if GENEVA_EXT
    /* not in the command list: that one is Geneva's (golden snapshots) */
    if (strcmp(cmd, "selftest") == 0)
        return xcmd_selftest(argc - 2, argv + 2);
#endif
    for (size_t i = 0; i < ARRAY_LEN(commands); i++)
        if (strcmp(cmd, commands[i].name) == 0) {
            int n = argc - 2;
            char **v = argv + 2;
#if GENEVA_EXT
            /* geneva CMD @FILE: the options from FILE (the commands with
             * --ext; it must be among them) */
            static const char *const with_ext[] = {"apply", "censor", "check", "eval", "evolve", "fw", "run"};
            sbuf err;
            int has = 0;
            for (size_t k = 0; k < ARRAY_LEN(with_ext); k++)
                has |= !strcmp(cmd, with_ext[k]);
            sb_init(&err);
            if (has && xcfg_expand(&n, &v, &err) < 0) {
                fprintf(stderr, "geneva %s: %s\n", cmd, err.data);
                sb_free(&err);
                return EXIT_USAGE;
            }
            sb_free(&err);
#endif
            return commands[i].fn(n, v);
        }
    fprintf(stderr, "geneva: unknown command \"%s\"\n\n", cmd);
    usage(stderr);
    return EXIT_USAGE;
}
