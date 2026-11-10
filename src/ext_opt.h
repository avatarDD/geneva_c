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
#define EXT_OPT {"ext", 0, 0, NULL, EXT_HELP("turn on the extensions beyond Geneva (docs/EXT.md)")}

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
