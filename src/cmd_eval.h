/* Probe and evaluator options shared by "geneva eval" and "geneva evolve". */
#ifndef GENEVA_CMD_EVAL_H
#define GENEVA_CMD_EVAL_H

#include <signal.h>

#include "args.h"
#include "evaluator.h"

#define EVAL_OPTS                                                                                  \
    {"probe", 0, 1, "KIND", "http (default), tls, dns, tcp, exec or external"},                    \
        {"host", 0, 1, "NAME", "Host header, TLS SNI, or the DNS name to query"},                  \
        {"ip", 0, 1, "ADDR", "address to connect to (default: resolve --host; dns: the resolver)"}, \
        {"port", 0, 1, "N", "port of the service (http 80, tls 443, dns 53)"},                     \
        {"path", 0, 1, "PATH", "http: request path (default /)"},                                  \
        {"bad-word", 0, 1, "WORD", "http: add ?q=WORD to the request, like Geneva"},               \
        {"valid-contains", 0, 1, "TEXT", "the answer must contain TEXT"},                          \
        {"injected-contains", 0, 1, "TEXT", "the censor's answer (block page) contains TEXT"},      \
        {"min-bytes", 0, 1, "N", "http, tls, tcp: at least N bytes must arrive"},                  \
        {"max-bytes", 0, 1, "N", "http, tcp: stop reading after N bytes (default 4 MB)"},          \
        {"tls-version", 0, 1, "V", "tls: 1.2, 1.3 or any (default)"},                              \
        {"alpn", 0, 1, "PROTO", "tls: ALPN protocol (default http/1.1)"},                          \
        {"dns-tcp", 0, 0, NULL, "dns: query over TCP"},                                            \
        {"dns-aaaa", 0, 0, NULL, "dns: ask for AAAA records"},                                     \
        {"dns-expect", 0, 1, "LIST", "dns: an answer must be in LIST (addresses or prefixes)"},    \
        {"dns-bad", 0, 1, "LIST", "dns: answers in LIST are forged"},                              \
        {"payload", 0, 1, "DATA", "tcp: bytes to send (\\r \\n \\xHH escapes, or hex:...)"},       \
        {"cmd", 0, 1, "COMMAND", "exec: command line; {lports} {lport} {host} {ip} {port}"},       \
        {"timeout", 0, 1, "SEC", "connection and read timeout (default 5; exec: whole run, 20)"},  \
        {"runs", 0, 1, "N", "runs per strategy (default 1)"},                                      \
        {"fitness-by", 0, 1, "HOW", "combine runs by avg (default), min or max"},                  \
        {"workers", 0, 1, "N", "strategies evaluated in parallel (default 1)"},                    \
        {"residual-wait", 0, 1, "SEC", "pause after a failed run (censors that keep blocking)"},  \
        {"local-ports", 0, 1, "BASE", "local ports for probes: 64 per worker from BASE (default 30000)"}, \
        {"no-engine", 0, 0, NULL, "probes only, no strategies (no privileges needed)"},            \
        {"agent", 0, 1, "ADDR", "server-side: geneva agent at ADDR (tcp:HOST:PORT) runs the probes"}, \
        {"agent-listen", 0, 1, "ADDR", "server-side: wait for geneva agent --connect on ADDR"},    \
        {"agent-token", 0, 1, "TOKEN", "the agent's token (default $GENEVA_AGENT_TOKEN)"},         \
        {"agent-wait", 0, 1, "SEC", "--agent-listen: wait for the agent this long (default 300)"}, \
        {"queue", 'q', 1, "N", "NFQUEUE number (default 311)"},                                    \
        {"mark", 0, 1, "MASK", "fwmark of packets the engine sends (default 0x20000000)"},         \
        {"firewall", 0, 1, "TYPE", "auto, nft or iptables"}

/* Reads EVAL_OPTS into o (the payload is allocated; free o->probe.payload).
 * Resolves the address. Prints an error and returns -1 on bad options. */
int eval_parse_args(const args_t *a, const char *cmd, eval_opts *o);

/* "http:example.com:80": the default target profile for the database. */
void eval_target_name(const eval_opts *o, sbuf *out);

/* SIGINT/SIGTERM (Ctrl+C on Windows) set *flag. */
void stop_on_signals(volatile sig_atomic_t *flag);

#endif
