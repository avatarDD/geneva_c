/*
 * "geneva censor": a lab censor on a Linux router. Forwarded packets of the
 * given ports go to NFQUEUE and through one of Geneva's censor models
 * (censor.h); a test client behind the router then searches for strategies
 * against it, as Geneva's evaluator does with its docker censors.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "censor.h"
#include "fw.h"
#include "geneva.h"
#include "log.h"
#include "pkt.h"
#include "plat.h"
#include "util.h"

#ifdef __linux__
#  include "nfq.h"
#  include "rawsend.h"
#endif

static void list_models(void)
{
    size_t n;
    const censor_info *m = censor_models(&n);
    for (size_t i = 0; i < n; i++)
        printf("%-4s %s\n", m[i].name, m[i].summary);
}

#ifdef __linux__

static volatile sig_atomic_t g_stop, g_reset;

static void on_signal(int sig)
{
    if (sig == SIGHUP)
        g_reset = 1;
    else
        g_stop = 1;
}

typedef struct {
    censor *cen;
    nfq *q;
    rawsend *rs;
    uint64_t packets, fired, blocked, dropped, injected, send_errors;
} cstate;

/* The address the router would send from towards dst (Geneva: the censor's
 * own address). */
static int route_src(int ver, const uint8_t *dst, uint8_t *out, void *ctx)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    int fd = socket(ver == 4 ? AF_INET : AF_INET6, SOCK_DGRAM, 0), rc = -1;
    if (fd < 0)
        return -1;
    memset(&ss, 0, sizeof(ss));
    if (ver == 4) {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(9);
        memcpy(&a->sin_addr, dst, 4);
        sl = sizeof(*a);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(9);
        memcpy(&a->sin6_addr, dst, 16);
        sl = sizeof(*a);
    }
    if (connect(fd, (struct sockaddr *)&ss, sl) == 0) {
        sl = sizeof(ss);
        if (getsockname(fd, (struct sockaddr *)&ss, &sl) == 0) {
            if (ver == 4)
                memcpy(out, &((struct sockaddr_in *)&ss)->sin_addr, 4);
            else
                memcpy(out, &((struct sockaddr_in6 *)&ss)->sin6_addr, 16);
            rc = 0;
        }
    }
    close(fd);
    return rc;
}

static void do_send(const uint8_t *pkt, size_t len, void *ctx)
{
    cstate *s = ctx;
    if (rawsend_send(s->rs, pkt, len) < 0) {
        s->send_errors++;
        LOGD("censor", "raw send: %s", strerror(errno));
    } else {
        s->injected++;
    }
}

static void put_addrs(jw *w, const uint8_t *p, size_t len)
{
    char a[INET6_ADDRSTRLEN], b[INET6_ADDRSTRLEN];
    int v6 = len >= 40 && p[0] >> 4 == 6;
    if (len < 20 || (!v6 && p[0] >> 4 != 4))
        return;
    inet_ntop(v6 ? AF_INET6 : AF_INET, p + (v6 ? 8 : 12), a, sizeof(a));
    inet_ntop(v6 ? AF_INET6 : AF_INET, p + (v6 ? 24 : 16), b, sizeof(b));
    jw_kstr(w, "src", a);
    jw_kstr(w, "dst", b);
    {
        size_t hl = v6 ? 40 : (size_t)(p[0] & 15) * 4;
        uint8_t proto = v6 ? p[6] : p[9];
        if ((proto == 6 || proto == 17) && len >= hl + 4) {
            jw_kstr(w, "proto", proto == 6 ? "tcp" : "udp");
            jw_kint(w, "sport", p[hl] << 8 | p[hl + 1]);
            jw_kint(w, "dport", p[hl + 2] << 8 | p[hl + 3]);
        }
    }
}

static void do_reset(cstate *s)
{
    g_reset = 0;
    censor_new_run(s->cen);
    LOGI("censor", "state reset");
    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "reset");
        ev_emit(&ev);
    }
}

static void on_msg(const nfq_msg *m, void *ctx)
{
    cstate *s = ctx;
    censor_result r;
    if (g_reset)
        do_reset(s); /* before the packet that follows the signal */
    s->packets++;
    censor_packet(s->cen, m->data, m->len, do_send, s, &r);
    if (log_enabled(LOG_TRACE)) {
        gpkt *p = pkt_parse(m->data, m->len);
        sbuf d;
        sb_init(&d);
        if (p)
            pkt_describe(p, &d);
        LOGT("censor", "%s %s%s", r.accept ? "accept" : "drop", d.len ? d.data : "(unparsed)",
             r.what == CENSOR_FIRED     ? " [censored]"
             : r.what == CENSOR_BLOCKED ? " [blocked]"
             : r.what == CENSOR_OLD     ? " [earlier run]"
                                        : "");
        sb_free(&d);
        pkt_free(p);
    }
    if (!r.accept)
        s->dropped++;
    if (r.what == CENSOR_FIRED)
        s->fired++;
    else if (r.what == CENSOR_BLOCKED)
        s->blocked++;
    if (r.what == CENSOR_CONTROL)
        LOGI("censor", "control packet (sport 2222, seq 13337): ready");
    if (r.what == CENSOR_FIRED) {
        LOGI("censor", "censored a packet: %s", r.action);
        if (ev_enabled()) {
            ev_t ev;
            ev_begin(&ev, "censorship");
            jw_kstr(&ev.w, "censor", censor_name(s->cen));
            jw_kstr(&ev.w, "action", r.action);
            put_addrs(&ev.w, m->data, m->len);
            jw_kint(&ev.w, "injected", r.sent);
            ev_emit(&ev);
        }
    } else if (r.what == CENSOR_BLOCKED) {
        LOGD("censor", "still blocked: %s", r.action);
    }
    if (nfq_verdict(s->q, m->id, r.accept ? NFQ_ACCEPT : NFQ_DROP, NULL, 0, 0, 0) < 0)
        LOGW("censor", "verdict for packet %u failed: %s", m->id, strerror(errno));
}

static void pass_msg(const nfq_msg *m, void *ctx)
{
    cstate *s = ctx;
    nfq_verdict(s->q, m->id, NFQ_ACCEPT, NULL, 0, 0, 0);
}

static int run_censor(censor *cen, fw_config *fw, int apply_fw, double duration)
{
    cstate s;
    nfq_config qc;
    sbuf err;
    int errnum, rc = EXIT_OK, fw_on = 0;
    uint64_t start = plat_now_ms(), overruns = 0;
    struct sigaction sa;
    const char *reason = "signal";

    memset(&s, 0, sizeof(s));
    s.cen = cen;
    censor_new_run(cen); /* track connections from the start, for SIGHUP */
    sb_init(&err);
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (ev_enabled()) {
        ev_t ev;
        sbuf ps;
        sb_init(&ps);
        ports_format(&fw->ports, &ps, ",", "-");
        ev_begin(&ev, "start");
        jw_kint(&ev.w, "proto", GENEVA_PROTO_VERSION);
        jw_kstr(&ev.w, "version", GENEVA_VERSION);
        jw_kstr(&ev.w, "mode", "censor");
        jw_kint(&ev.w, "pid", (int64_t)getpid());
        jw_kstr(&ev.w, "censor", censor_name(cen));
        jw_kint(&ev.w, "queue", fw->queue);
        jw_kstr(&ev.w, "ports", ps.data);
        ev_emit(&ev);
        sb_free(&ps);
    }

    memset(&qc, 0, sizeof(qc));
    qc.queue = fw->queue;
    qc.maxlen = 4096;
    qc.rcvbuf = 4 << 20;
    s.q = nfq_open(&qc, &errnum, &err);
    if (!s.q) {
        LOGE("censor", "%s", err.data);
        rc = (errnum == EPERM || errnum == EACCES || errnum == EPROTONOSUPPORT) ? EXIT_PRIV : EXIT_FAIL;
        goto out;
    }
    s.rs = rawsend_open(fw->mark, &err);
    if (!s.rs) {
        LOGE("censor", "%s", err.data);
        rc = EXIT_PRIV;
        goto out;
    }
    sb_reset(&err);
    if (apply_fw) {
        if (fw_up(fw, &err) < 0) {
            LOGE("censor", "firewall: %s", err.data);
            rc = EXIT_FIREWALL;
            goto out;
        }
        fw_on = 1;
    }
    LOGI("censor", "censor %s on NFQUEUE %u (firewall %s)", censor_name(cen), fw->queue,
         apply_fw ? fw_backend_name(fw->backend) : "none");
    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "ready");
        jw_kstr(&ev.w, "backend", "nfqueue");
        jw_kstr(&ev.w, "firewall", apply_fw ? fw_backend_name(fw->backend) : "none");
        ev_emit(&ev);
    }

    while (!g_stop) {
        struct pollfd pfd = {nfq_fd(s.q), POLLIN, 0};
        int r;
        if (g_reset)
            do_reset(&s);
        if (duration > 0 && plat_now_ms() - start >= (uint64_t)(duration * 1000)) {
            reason = "duration";
            break;
        }
        r = poll(&pfd, 1, 100);
        if (r < 0 && errno != EINTR) {
            LOGE("censor", "poll: %s", strerror(errno));
            rc = EXIT_FAIL;
            break;
        }
        if (r <= 0)
            continue;
        for (int i = 0; i < 64; i++) {
            r = nfq_read(s.q, on_msg, &s, &overruns);
            if (r < 0) {
                LOGE("censor", "NFQUEUE read: %s", strerror(errno));
                rc = EXIT_FAIL;
                g_stop = 1;
                break;
            }
            if (r == 0)
                break;
        }
    }
out:
    if (fw_on)
        fw_down(fw);
    if (s.q) {
        while (nfq_read(s.q, pass_msg, &s, NULL) > 0)
            ;
        nfq_close(s.q);
    }
    if (s.rs)
        rawsend_close(s.rs);
    LOGI("censor", "%llu packets, censored %llu, blocked %llu more, dropped %llu, sent %llu",
         (unsigned long long)s.packets, (unsigned long long)s.fired, (unsigned long long)s.blocked,
         (unsigned long long)s.dropped, (unsigned long long)s.injected);
    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "stats");
        jw_kint(&ev.w, "uptime_ms", (int64_t)(plat_now_ms() - start));
        jw_kint(&ev.w, "packets", (int64_t)s.packets);
        jw_kint(&ev.w, "censored", (int64_t)s.fired);
        jw_kint(&ev.w, "blocked", (int64_t)s.blocked);
        jw_kint(&ev.w, "dropped", (int64_t)s.dropped);
        jw_kint(&ev.w, "injected", (int64_t)s.injected);
        jw_kint(&ev.w, "send_errors", (int64_t)s.send_errors);
        jw_kint(&ev.w, "overruns", (int64_t)overruns);
        ev_emit(&ev);
        ev_begin(&ev, "exit");
        jw_kint(&ev.w, "code", rc);
        jw_kstr(&ev.w, "reason", rc == EXIT_OK ? reason : "error");
        ev_emit(&ev);
    }
    sb_free(&err);
    return rc;
}

#endif /* __linux__ */

static int parse_addr(const char *s, censor_cfg *c, int dns)
{
    uint8_t b[16];
    int v6 = strchr(s, ':') != NULL;
    if (inet_pton(v6 ? AF_INET6 : AF_INET, s, b) != 1)
        return -1;
    if (dns) {
        memcpy(v6 ? c->dns_aaaa : c->dns_a, b, v6 ? 16 : 4);
    } else if (v6) {
        memcpy(c->ip6, b, 16);
        c->has_ip6 = 1;
    } else {
        memcpy(c->ip4, b, 4);
        c->has_ip4 = 1;
    }
    return 0;
}

int cmd_censor(int argc, char **argv)
{
    static const optdef defs[] = {
        {"censor", 'c', 1, "NAME", "censor model: 1-11, 8b or dns (see --list)"},
        {"list", 0, 0, NULL, "list the censor models"},
        {"port", 'p', 1, "PORTS", "ports of the censored service (default 80; dns: 53)"},
        {"forbidden", 'w', 1, "WORD", "forbidden content (repeatable; default ultrasurf)"},
        {"censor-ip", 0, 1, "ADDR", "source of RSTs to the server: client (default), router (as Geneva) or an address"},
        {"dns-answer", 0, 1, "ADDR", "dns: forged A or AAAA answer (default 10.10.34.34, 2001:db8::34)"},
        {"queue", 'q', 1, "N", "NFQUEUE number (default 400)"},
        {"mark", 0, 1, "MASK", "fwmark of the packets the censor sends (default 0x20000000)"},
        {"firewall", 0, 1, "TYPE", "auto, nft, iptables, or none (rules set up by hand)"},
        {"iface", 'i', 1, "IF", "only packets that arrive on this interface"},
        {"duration", 0, 1, "SEC", "stop after SEC seconds"},
        {"events", 'e', 1, "SINK", "JSON Lines events: - (stdout), stderr, FILE or none"},
        {"log-level", 'l', 1, "LEVEL", "error, warn, info (default), debug or trace"},
        {"log-format", 0, 1, "FMT", "text (default) or json"},
        {"log-file", 0, 1, "FILE", "also write the log to FILE"},
        {"verbose", 'v', 0, NULL, "same as --log-level trace"},
        {"quiet", 0, 0, NULL, "no log on stderr"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    censor_cfg cfg;
    censor *cen = NULL;
    fw_config fw;
    const char *s, *name;
    int idx, rc = EXIT_USAGE, apply_fw = 1;
    int64_t v;
    double duration;
    sbuf e;

    sb_init(&e);
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva censor: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva censor -c NAME [options]\n"
                  "Runs a lab censor of Geneva on a Linux router: packets forwarded to and from\n"
                  "PORTS pass through it. Needs root. SIGHUP resets the censor's state (Geneva\n"
                  "starts a fresh censor for every strategy); SIGINT/SIGTERM stop it and\n"
                  "remove the firewall rules. See docs/CENSOR.md.",
                  defs);
        rc = EXIT_OK;
        goto done;
    }
    if (arg_has(&a, "list")) {
        list_models();
        rc = EXIT_OK;
        goto done;
    }
    if (a.npos) {
        fprintf(stderr, "geneva censor: unexpected argument \"%s\"\n", a.pos[0]);
        goto done;
    }
    if (!(name = arg_str(&a, "censor", NULL))) {
        fprintf(stderr, "geneva censor: need --censor NAME (1-11, 8b or dns; --list shows them)\n");
        goto done;
    }
    censor_cfg_default(&cfg);
    idx = 0;
    if (arg_has(&a, "forbidden")) {
        cfg.nwords = 0;
        while ((s = arg_next(&a, "forbidden", &idx)) != NULL) {
            if (!*s || cfg.nwords == CENSOR_MAX_WORDS) {
                fprintf(stderr, "geneva censor: up to %d non-empty --forbidden words\n", CENSOR_MAX_WORDS);
                goto done;
            }
            cfg.words[cfg.nwords++] = s;
        }
    }
    idx = 0;
    while ((s = arg_next(&a, "censor-ip", &idx)) != NULL) {
        cfg.spoof_client = !strcmp(s, "client");
        if (cfg.spoof_client || !strcmp(s, "router"))
            continue;
        if (parse_addr(s, &cfg, 0) < 0) {
            fprintf(stderr, "geneva censor: --censor-ip takes client, router or an address, not %s\n", s);
            goto done;
        }
    }
    idx = 0;
    while ((s = arg_next(&a, "dns-answer", &idx)) != NULL)
        if (parse_addr(s, &cfg, 1) < 0) {
            fprintf(stderr, "geneva censor: bad --dns-answer %s\n", s);
            goto done;
        }
#ifdef __linux__
    cfg.local_addr = route_src;
#endif
    if (!(cen = censor_new(name, &cfg, &e))) {
        fprintf(stderr, "geneva censor: %s\n", e.data);
        goto done;
    }

    fw_config_default(&fw);
    fw.forward = 1;
    fw.queue = 400;
    if (!strcmp(censor_name(cen), "dns"))
        fw.tcp = 0, fw.udp = 1;
    if (ports_parse(arg_str(&a, "port", fw.udp ? "53" : "80"), &fw.ports) < 0) {
        fprintf(stderr, "geneva censor: bad --port (like 80 or 80,443 or 8000-8100)\n");
        goto done;
    }
    if (arg_int(&a, "queue", 400, 0, 65535, &v) < 0)
        goto done;
    fw.queue = (uint16_t)v;
    if ((s = arg_str(&a, "mark", NULL)) != NULL) {
        char *end;
        unsigned long m = strtoul(s, &end, 0);
        if (*end || !m || m > 0xffffffffUL) {
            fprintf(stderr, "geneva censor: bad --mark %s\n", s);
            goto done;
        }
        fw.mark = (uint32_t)m;
    }
    if ((s = arg_str(&a, "firewall", NULL)) != NULL) {
        if (!strcmp(s, "none"))
            apply_fw = 0;
        else if (fw_backend_parse(s, &fw.backend) < 0) {
            fprintf(stderr, "geneva censor: --firewall must be auto, nft, iptables or none\n");
            goto done;
        }
    }
    fw.iface = arg_str(&a, "iface", NULL);
    if (fw.iface && (strlen(fw.iface) >= 16 || strpbrk(fw.iface, " \t\"'\\;"))) {
        fprintf(stderr, "geneva censor: bad interface name\n");
        goto done;
    }
    if (arg_dbl(&a, "duration", 0, 0, 1e9, &duration) < 0 || parse_logging(&a, "censor") < 0)
        goto done;
#ifdef __linux__
    rc = run_censor(cen, &fw, apply_fw, duration);
#else
    (void)apply_fw;
    fprintf(stderr, "geneva censor: runs on Linux routers only (NFQUEUE)\n");
    rc = EXIT_PRIV;
#endif
done:
    censor_free(cen);
    sb_free(&e);
    args_free(&a);
    return rc;
}
