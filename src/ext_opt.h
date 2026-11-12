/*
 * The --ext switch (docs/EXT_ROADMAP.md): the extensions for parity with
 * zapret2 live in src/ext/ and work only when a command gets --ext. Without
 * --ext every command behaves exactly as before (tests/golden). A build with
 * "make EXT=0" has no src/ext/ at all and refuses --ext.
 */
#ifndef GENEVA_EXT_OPT_H
#define GENEVA_EXT_OPT_H

#include "args.h"

#ifndef GENEVA_EXT
#  define GENEVA_EXT 1
#endif

/* Help text of an option that works only with --ext. args_help() lists such
 * options apart, under "Extensions (with --ext):" after the usual ones, so
 * that the legacy part of every help text stays as it was. In a build
 * without src/ext/ (make EXT=0) they have no help and are not listed. */
#define EXT_HELP_MARK "\001"
#if GENEVA_EXT
#  define EXT_HELP(s) EXT_HELP_MARK s
#else
#  define EXT_HELP(s) NULL
#endif

/* The option row every command with extensions puts into its table. The
 * extensions are described in docs/EXT.md, and integrators find them as
 * the "ext" feature of "version --json". */
#define EXT_OPT                                                                                               \
    {"ext", 0, 0, NULL, EXT_HELP("turn on the extensions beyond Geneva (docs/EXT.md); geneva CMD @FILE "      \
                                 "takes the options from FILE (with --ext)")},                                  \
    {"comment", 0, 2, "TEXT", EXT_HELP("ignored (a note in an @FILE)")}

/* Running as a service (run): zapret2's names, with --ext */
#define EXT_RUN_OPTS                                                                                          \
    {"dry-run", 0, 0, NULL, EXT_HELP("check the options, the strategies and the lists, then exit (0: fine)")}, \
    {"daemon", 0, 0, NULL, EXT_HELP("go to the background once packets flow (the exit code tells a failed "   \
                                    "start)")},                                                               \
    {"pidfile", 0, 1, "FILE", EXT_HELP("write the process id to FILE (removed on exit)")},                    \
    {"user", 0, 1, "NAME", EXT_HELP("Linux: once running, become NAME, keeping CAP_NET_ADMIN and CAP_NET_RAW " \
                                    "(a root helper removes the rules on exit)")},                           \
    {"uid", 0, 1, "UID[:GID,..]", EXT_HELP("the same with numbers")},                                          \
    {"ext-seccomp", 0, 2, "0|1", EXT_HELP("Linux: once running, forbid exec, kill, ptrace and file system "   \
                                          "changes (1; the root helper removes the rules on exit)")},         \
    {"log-target", 0, 1, "syslog", EXT_HELP("also log to syslog (/dev/log)")},                              \
    {"ext-workers", 0, 1, "N|auto",                                                                           \
     EXT_HELP("Linux: N worker threads, each with its own NFQUEUE (--queue .. --queue+N-1, the rules "        \
              "balance the flows by address); auto: the CPUs, at most 4 (default 1)")}

/* --ext-auto (run; src/ext/auto.h) */
#define EXT_AUTO_OPTS                                                                                         \
    {"ext-auto", 0, 1, "observe",                                                                             \
     EXT_HELP("watch the PC's own flows on any port and tell of blocked keys (port, /24 or /48, "           \
              "address, host): Linux sees the first packets (NFLOG) and the conntrack's counters "          \
              "(ctnetlink, once a second: freezes, throttling); Windows every packet (a WinDivert "         \
              "sniff handle, the bytes counted itself); events ext_flow, ext_impaired, ext_class, "         \
              "ext_link, ctl ext_status; traffic is not changed")},                                         \
    {"ext-nflog-group", 0, 1, "N", EXT_HELP("Linux: the NFLOG group of --ext-auto (the queue number)")},       \
    {"ext-observe-first", 0, 1, "N",                                                                          \
     EXT_HELP("Linux: --ext-auto's packets of each direction observed per flow (16)")}

/* The firewall's (run and fw): zapret2's rules and winws2's --wf-* filter,
 * with --ext (src/ext/fwx.c) */
#define EXT_FW_OPTS                                                                                           \
    {"ext-first", 0, 1, "N|SPEC",                                                                             \
     EXT_HELP("--first per protocol and direction: [tcp-|udp-]out=N,[tcp-|udp-]in=N,... (zapret2's: "        \
              "tcp-out=20,tcp-in=10,udp-out=5,udp-in=3; 0: every packet)")},                                \
    {"ext-wan", 0, 1, "IF,..", EXT_HELP("like --iface, up to 8 interfaces (Windows: indexes)")},                          \
    {"ext-lan", 0, 1, "IF,..", EXT_HELP("Linux: the LAN interfaces of --ext-flowoffload")},                  \
    {"ext-notrack", 0, 1, "all|frag|none",                                                                   \
     EXT_HELP("Linux: the packets the engine sends kept out of conntrack: all (default), frag: IP fragments " \
              "and TCP without SYN/RST/ACK only (zapret2), none (--no-notrack)")},                           \
    {"ext-ttl-icmp", 0, 0, NULL,                                                                              \
     EXT_HELP("Linux: drop ICMP time-exceeded of the queued flows (fakes with a small TTL make them; ct mark " \
              "--mark)")},                                                                                    \
    {"ext-flowoffload", 0, 1, "none|software|hardware",                                                      \
     EXT_HELP("Linux, nft: our flowtable over --iface/--ext-wan and --ext-lan, the queued flows kept out of " \
              "it while queued (turn the system's flow offload off)")},                                      \
    {"fw-hook-pre", 0, 1, "FILE", EXT_HELP("Linux: run FILE up|down BACKEND QUEUE before the rules go up or down")}, \
    {"fw-hook-post", 0, 1, "FILE", EXT_HELP("Linux: the same after them")},                                    \
    {"wf-tcp-out", 0, 1, "[~]P[-P],..", EXT_HELP("WinDivert filter of winws2 (replaces the one from -p): TCP to " \
                                                 "these ports")},                                             \
    {"wf-tcp-in", 0, 1, "[~]P[-P],..", EXT_HELP("... TCP from these ports (incoming connections)")},          \
    {"wf-udp-out", 0, 1, "[~]P[-P],..", EXT_HELP("... UDP to these ports")},                                 \
    {"wf-udp-in", 0, 1, "[~]P[-P],..", EXT_HELP("... UDP from these ports")},                                \
    {"wf-icmp-out", 0, 1, "T[:C],..|*", EXT_HELP("... outgoing ICMP of these types[:codes]")},               \
    {"wf-icmp-in", 0, 1, "T[:C],..|*", EXT_HELP("... incoming ICMP of these types[:codes]")},                \
    {"wf-ipp-out", 0, 1, "PROTO,..|*", EXT_HELP("... outgoing packets of these IP protocols")},              \
    {"wf-ipp-in", 0, 1, "PROTO,..|*", EXT_HELP("... incoming packets of these IP protocols")},               \
    {"wf-iface", 0, 1, "IDX[.SUB]", EXT_HELP("... only this interface index")},                              \
    {"wf-l3", 0, 1, "ipv4,ipv6", EXT_HELP("... only these IP versions")},                                    \
    {"wf-tcp-empty", 0, 2, "0|1", EXT_HELP("... also TCP without data and SYN/RST/FIN (0)")},                \
    {"wf-raw-part", 0, 1, "EXPR|@FILE", EXT_HELP("... or this expression; repeatable")},                     \
    {"wf-raw-filter", 0, 1, "EXPR|@FILE", EXT_HELP("... and this expression")},                              \
    {"wf-filter-lan", 0, 1, "0|1", EXT_HELP("... without private and link-local addresses (1)")},             \
    {"wf-filter-loopback", 0, 1, "0|1", EXT_HELP("... without loopback (1)")},                               \
    {"wf-raw", 0, 1, "EXPR|@FILE", EXT_HELP("the whole WinDivert filter, as it is")},                       \
    {"wf-priority", 0, 1, "N", EXT_HELP("the same as --priority")},                                          \
    {"wf-dup-check", 0, 2, "0|1", EXT_HELP("accepted and ignored (WinDivert takes several handles)")},       \
    {"wf-save", 0, 1, "FILE", EXT_HELP("write the --wf-* filter to FILE and exit (any platform)")}

/* The conntrack and the L7 of the extensions (FLOW: and L7: triggers), for
 * the commands that run strategies: run, eval, evolve, apply. */
#define EXT_CTRACK_OPTS                                                                                       \
    {"ext-ctrack-timeouts", 0, 1, "S:E:F[:U]",                                                                \
     EXT_HELP("conntrack timeouts, s: TCP SYN, ESTABLISHED, FIN, UDP (60:300:60:60)")},                       \
    {"ext-ctrack-max", 0, 1, "N", EXT_HELP("flows the conntrack keeps per worker (16384)")},                   \
    {"ext-ctrack-disable", 0, 0, NULL, EXT_HELP("no conntrack: FLOW triggers match only the \"a\" range")},      \
    {"ext-payload-disable", 0, 1, "LIST",                                                                     \
     EXT_HELP("payload types not to recognize (L7:payload), e.g. dht,stun, or all")},                    \
    {"ext-reasm-disable", 0, 1, "LIST",                                                                       \
     EXT_HELP("do not reassemble a ClientHello split over packets: tls_client_hello, quic_initial or all")},   \
    {"ext-reasm-max", 0, 1, "BYTES", EXT_HELP("the longest ClientHello reassembled (16384)")},               \
    {"ext-blob", 0, 1, "NAME:0xHEX|NAME:[+OFS]@FILE",                                                        \
     EXT_HELP("a blob for the x-actions (blob=NAME); built in: fake_default_tls, fake_default_http, "         \
              "fake_default_quic, fake_quic_initial; repeatable")},                                           \
    {"ext-bind-fix4", 0, 0, NULL, EXT_HELP("send x-action packets through the packet's interface (IPv4)")},     \
    {"ext-bind-fix6", 0, 0, NULL, EXT_HELP("the same for IPv6")}

/* The profiles (docs/EXT.md, src/ext/profile.h) for run and apply: zapret2's
 * names, so not under "ext-"; they too need --ext. */
#define EXT_PROFILE_OPTS                                                                                       \
    {"new", 0, 2, "NAME", EXT_HELP("start the next profile (its own -s/-f and filters)")},                    \
    {"name", 0, 1, "NAME", EXT_HELP("the name of this profile")},                                            \
    {"skip", 0, 0, NULL, EXT_HELP("leave this profile out")},                                                \
    {"template", 0, 2, "NAME", EXT_HELP("this profile is a template for --import, not a profile")},          \
    {"import", 0, 1, "NAME", EXT_HELP("copy the filters and the strategy of template NAME")},               \
    {"filter-l3", 0, 1, "ipv4,ipv6", EXT_HELP("the profile takes these IP versions")},                       \
    {"filter-tcp", 0, 1, "[~]P[-P],..|*", EXT_HELP("the profile takes TCP to these server ports")},          \
    {"filter-udp", 0, 1, "[~]P[-P],..|*", EXT_HELP("the profile takes UDP to these server ports")},          \
    {"filter-icmp", 0, 1, "T[:C],..|*", EXT_HELP("the profile takes ICMP of these types[:codes]")},         \
    {"filter-ipp", 0, 1, "PROTO,..|*", EXT_HELP("the profile takes these other IP protocols")},             \
    {"filter-l7", 0, 1, "LIST", EXT_HELP("the profile takes flows of these L7 protocols (tls,quic,http,...)")}, \
    {"filter-mark", 0, 1, "MARK[/MASK]", EXT_HELP("the profile takes packets with this fwmark")},           \
    {"hostlist", 0, 1, "FILE", EXT_HELP("the profile takes hosts of FILE and their subdomains (^NAME: no subdomains, "    \
                                        "!NAME: never; gzip ok; re-read on change); repeatable")},      \
    {"hostlist-domains", 0, 1, "NAME,..", EXT_HELP("the same with the names given here")},                 \
    {"hostlist-exclude", 0, 1, "FILE", EXT_HELP("the profile does not take hosts of FILE")},                \
    {"hostlist-exclude-domains", 0, 1, "NAME,..", EXT_HELP("the same with the names given here")},         \
    {"ipset", 0, 1, "FILE", EXT_HELP("the profile takes servers of FILE (IPv4/IPv6 addresses and subnets; " \
                                     "gzip ok; re-read on change); repeatable")},                            \
    {"ipset-ip", 0, 1, "CIDR,..", EXT_HELP("the same with the subnets given here")},                       \
    {"ipset-exclude", 0, 1, "FILE", EXT_HELP("the profile does not take servers of FILE")},                 \
    {"ipset-exclude-ip", 0, 1, "CIDR,..", EXT_HELP("the same with the subnets given here")},               \
    {"hostlist-auto", 0, 1, "FILE",                                                                            \
     EXT_HELP("autolist: a host of this profile that fails without the strategy is added to FILE (created "   \
              "when missing; it is a --hostlist of the profile too)")},                                        \
    {"hostlist-auto-fail-threshold", 0, 1, "N", EXT_HELP("failures that add a host (3; 1..20)")},             \
    {"hostlist-auto-fail-time", 0, 1, "SEC", EXT_HELP("... within SEC seconds (60)")},                        \
    {"hostlist-auto-retrans-threshold", 0, 1, "N",                                                            \
     EXT_HELP("TCP: N retransmissions of the client's request are a failure (3; 2..10)")},                   \
    {"hostlist-auto-retrans-maxseq", 0, 1, "BYTES",                                                           \
     EXT_HELP("... counted within the client's first BYTES; past them the site works (32768)")},             \
    {"hostlist-auto-retrans-reset", 0, 2, "0|1",                                                              \
     EXT_HELP("send the client a RST after a retransmission failure (1)")},                                  \
    {"hostlist-auto-incoming-maxseq", 0, 1, "BYTES",                                                          \
     EXT_HELP("TCP: a RST or an HTTP redirect to another domain within the server's first BYTES is a "        \
              "failure, data past them a success (4096; 0: off)")},                                          \
    {"hostlist-auto-udp-out", 0, 1, "N",                                                                      \
     EXT_HELP("UDP: N packets out with at most --hostlist-auto-udp-in back are a failure (4; 0: off)")},     \
    {"hostlist-auto-udp-in", 0, 1, "N", EXT_HELP("... and more than N back a success (1)")},                  \
    {"hostlist-auto-debug", 0, 1, "FILE", EXT_HELP("log every autolist decision to FILE")},                    \
    {"ext-ipcache-lifetime", 0, 1, "SEC",                                                                     \
     EXT_HELP("how long the IP cache keeps an address's host name and TTL (7200; 0: for ever)")},             \
    {"ext-ipcache-hostname", 0, 2, "0|1",                                                                     \
     EXT_HELP("cache host names by address (from DNS answers and flows) for the next flows' profile search")}, \
    {"ext-profile", 0, 1, "FILE", EXT_HELP("profiles from FILE ([profile NAME] sections; after those of the "  \
                                           "command line); repeatable")}

/* The options of the command itself: those before the first --new (the
 * later ones are other profiles'), for -s and -f. A view into a. */
args_t ext_cmd_args(const args_t *a);

/* After args_parse: takes --ext and checks that no --ext-* option comes
 * without it. Prints "geneva CMD: ..." and returns -1 on a usage error
 * (exit code 2), 0 otherwise. */
int ext_parse_args(const args_t *a, const char *cmd);

/* 1 once a command took --ext. */
int ext_enabled(void);

/* For tests: forget the switch. */
void ext_reset(void);

#endif
