/*
 * "geneva agent": makes the probes of a server-side evaluation from inside
 * the censored network (agent.h). Needs no privileges.
 *
 *   geneva agent --listen tcp:0.0.0.0:7110 --token SECRET
 *   geneva agent --connect tcp:203.0.113.5:7111 --token SECRET
 */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent.h"
#include "args.h"
#include "cmd_eval.h"
#include "ctl.h"
#include "geneva.h"
#include "log.h"
#include "plat.h"
#include "ports.h"

#define AGENT_DEFAULT_LISTEN "tcp:7110"

static void emit_state(const char *name, const char *addr)
{
    ev_t e;
    if (!ev_enabled())
        return;
    ev_begin(&e, name);
    jw_kstr(&e.w, "addr", addr);
    ev_emit(&e);
}

/* Serves c until stop, or (dial mode) until its last client is gone. */
static void serve(ctl *c, agent_state *st, volatile sig_atomic_t *stop, int dial)
{
    while (!*stop && (!dial || ctl_clients(c))) {
        plat_pollfd fds[CTL_MAX_CLIENTS + 1];
        size_t n = ctl_pollfds(c, fds, ARRAY_LEN(fds));
        int r = plat_poll(fds, (unsigned)n, 200);
        if (r > 0)
            ctl_dispatch(c, fds, n, agent_handler, st);
    }
}

int cmd_agent(int argc, char **argv)
{
    static const optdef defs[] = {
        {"listen", 'L', 1, "ADDR", "wait for the evaluator on ADDR (default " AGENT_DEFAULT_LISTEN ", loopback)"},
        {"connect", 'C', 1, "ADDR", "dial the evaluator's --agent-listen at ADDR (tcp:HOST:PORT)"},
        {"token", 't', 1, "TOKEN", "shared secret (default $GENEVA_AGENT_TOKEN); needed off loopback"},
        {"retry", 0, 1, "SEC", "--connect: pause before dialing again (default 5)"},
        {"local-ports", 0, 1, "LO-HI", "local ports of the probes (default: any)"},
        {"duration", 0, 1, "SEC", "exit after SEC seconds (default: run until stopped)"},
        {"events", 'e', 1, "SINK", "JSON Lines events: - (stdout), stderr, FILE or none"},
        {"log-level", 'l', 1, "LEVEL", "error, warn, info (default), debug or trace"},
        {"log-format", 0, 1, "FMT", "text (default) or json"},
        {"log-file", 0, 1, "FILE", "also write the log to FILE"},
        {"verbose", 'v', 0, NULL, "same as --log-level trace"},
        {"quiet", 0, 0, NULL, "no log on stderr"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    static volatile sig_atomic_t stop;
    args_t a;
    char aerr[128];
    const char *listen_addr, *connect_addr, *token, *s;
    agent_state st;
    double retry, duration;
    uint64_t start = plat_now_ms();
    ctl *c = NULL;
    sbuf err;
    int rc = EXIT_USAGE;

    if (args_parse(&a, argc, argv, defs, aerr, sizeof(aerr)) < 0) {
        fprintf(stderr, "geneva agent: %s\n", aerr);
        return EXIT_USAGE;
    }
    sb_init(&err);
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva agent [--listen ADDR | --connect ADDR] [--token TOKEN]\n"
                  "Runs the probes of a server-side evaluation (geneva eval/evolve --agent) from\n"
                  "this machine, inside the censored network. Needs no privileges. Only http,\n"
                  "tls, dns and tcp probes are run; one at a time. See docs/SERVER_SIDE.md.",
                  defs);
        rc = EXIT_OK;
        goto done;
    }
    if (a.npos) {
        fprintf(stderr, "geneva agent: unexpected argument \"%s\"\n", a.pos[0]);
        goto done;
    }
    connect_addr = arg_str(&a, "connect", NULL);
    listen_addr = arg_str(&a, "listen", connect_addr ? NULL : AGENT_DEFAULT_LISTEN);
    if (connect_addr && listen_addr) {
        fprintf(stderr, "geneva agent: --listen and --connect exclude each other\n");
        goto done;
    }
    token = arg_str(&a, "token", getenv("GENEVA_AGENT_TOKEN"));
    if (token && !*token)
        token = NULL;
    if (connect_addr && !token) {
        fprintf(stderr, "geneva agent: --connect needs --token\n");
        goto done;
    }
    memset(&st, 0, sizeof(st));
    if ((s = arg_str(&a, "local-ports", NULL)) != NULL) {
        portset p;
        if (ports_parse(s, &p) < 0 || p.n != 1) {
            fprintf(stderr, "geneva agent: --local-ports takes one range like 40000-40999\n");
            goto done;
        }
        st.ports.lo = p.lo[0];
        st.ports.hi = p.hi[0];
    }
    if (arg_dbl(&a, "retry", 5, 0.1, 3600, &retry) < 0 || arg_dbl(&a, "duration", 0, 0, 1e9, &duration) < 0 ||
        parse_logging(&a, "agent") < 0)
        goto done;

    stop_on_signals(&stop);
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "start");
        jw_kint(&e.w, "proto", GENEVA_PROTO_VERSION);
        jw_kstr(&e.w, "version", GENEVA_VERSION);
        jw_kstr(&e.w, "mode", "agent");
        jw_kint(&e.w, "pid", plat_getpid());
        ev_emit(&e);
    }
    if (listen_addr) {
        c = ctl_open(listen_addr, token, &err);
        if (!c) {
            fprintf(stderr, "geneva agent: %s\n", err.data);
            rc = EXIT_IO;
            goto done;
        }
        LOGI("agent", "waiting for the evaluator on %s", listen_addr);
        emit_state("ready", listen_addr);
        while (!stop && !(duration > 0 && plat_now_ms() - start >= (uint64_t)(duration * 1000))) {
            plat_pollfd fds[CTL_MAX_CLIENTS + 1];
            size_t n = ctl_pollfds(c, fds, ARRAY_LEN(fds));
            if (plat_poll(fds, (unsigned)n, 200) > 0)
                ctl_dispatch(c, fds, n, agent_handler, &st);
        }
    } else {
        c = ctl_new(token);
        emit_state("ready", connect_addr);
        while (!stop && !(duration > 0 && plat_now_ms() - start >= (uint64_t)(duration * 1000))) {
            sock_t sk;
            sb_reset(&err);
            sk = ctl_connect(connect_addr, &err);
            if (sk == SOCK_INVALID) {
                LOGD("agent", "%s", err.data);
            } else {
                LOGI("agent", "connected to the evaluator at %s", connect_addr);
                emit_state("connected", connect_addr);
                ctl_adopt(c, sk);
                serve(c, &st, &stop, 1);
                LOGI("agent", "the evaluator closed the connection");
                emit_state("disconnected", connect_addr);
            }
            for (uint64_t end = plat_now_ms() + (uint64_t)(retry * 1000); !stop && plat_now_ms() < end;) {
                if (duration > 0 && plat_now_ms() - start >= (uint64_t)(duration * 1000))
                    break;
                plat_sleep_ms(100);
            }
        }
    }
    LOGI("agent", "%llu probes run", (unsigned long long)st.probes);
    rc = EXIT_OK;
    if (ev_enabled()) {
        ev_t e;
        ev_begin(&e, "exit");
        jw_kint(&e.w, "code", rc);
        jw_kuint(&e.w, "probes", st.probes);
        ev_emit(&e);
    }
done:
    ctl_close(c);
    sb_free(&err);
    args_free(&a);
    return rc;
}
