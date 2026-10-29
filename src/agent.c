/*
 * Server-side evaluation: the agent and its client (see agent.h).
 */
#include "agent.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctl.h"
#include "geneva.h"
#include "log.h"
#include "plat.h"

/* ---- probe settings as JSON ---------------------------------------------- */

static void kstr_opt(jw *w, const char *k, const char *v)
{
    if (v)
        jw_kstr(w, k, v);
}

void agent_probe_json(const probe_cfg *c, jw *w)
{
    jw_key(w, "probe");
    jw_obj(w);
    jw_kstr(w, "kind", probe_kind_name(c->kind));
    kstr_opt(w, "host", c->host);
    if (c->addrlen) {
        /* resolved here: the agent's resolver may be the censored one */
        char ip[64];
        probe_addr_text(c, ip, sizeof(ip));
        jw_kstr(w, "ip", ip);
    } else {
        kstr_opt(w, "ip", c->ip);
    }
    jw_kint(w, "port", c->port);
    jw_kdbl(w, "timeout", c->timeout);
    kstr_opt(w, "path", c->path);
    kstr_opt(w, "bad_word", c->bad_word);
    kstr_opt(w, "valid_contains", c->valid_contains);
    kstr_opt(w, "injected_contains", c->injected_contains);
    if (c->min_bytes)
        jw_kuint(w, "min_bytes", c->min_bytes);
    if (c->max_bytes)
        jw_kuint(w, "max_bytes", c->max_bytes);
    if (c->tls_version)
        jw_kint(w, "tls_version", c->tls_version);
    kstr_opt(w, "alpn", c->alpn);
    if (c->dns_tcp)
        jw_kbool(w, "dns_tcp", 1);
    if (c->dns_aaaa)
        jw_kbool(w, "dns_aaaa", 1);
    kstr_opt(w, "dns_expect", c->dns_expect);
    kstr_opt(w, "dns_bad", c->dns_bad);
    if (c->payload_len) {
        sbuf h;
        sb_init(&h);
        sb_puts(&h, "hex:");
        hex_encode(&h, c->payload, c->payload_len);
        jw_kstr(w, "payload", h.data);
        sb_free(&h);
    }
    jw_obj_end(w);
}

/* A string member, or NULL; a member of another type is an error. */
static int get_str(const json_val *o, const char *k, const char **out, sbuf *err)
{
    const json_val *v = json_get(o, k);
    *out = NULL;
    if (!v || v->type == JSON_NULL)
        return 0;
    if (v->type != JSON_STR || strlen(v->str) > 1024) {
        sb_printf(err, "\"%s\" must be a string", k);
        return -1;
    }
    *out = v->str;
    return 0;
}

int agent_probe_parse(const json_val *o, probe_cfg *c, sbuf *err)
{
    const char *kind, *payload;
    int64_t port, tls, minb, maxb;
    double timeout;

    memset(c, 0, sizeof(*c));
    if (!o || o->type != JSON_OBJ) {
        sb_puts(err, "missing \"probe\" object");
        return -1;
    }
    kind = json_get_str(o, "kind", "http");
    if (probe_kind_parse(kind, &c->kind) < 0) {
        sb_printf(err, "unknown probe \"%s\"", kind);
        return -1;
    }
    if (c->kind == PROBE_EXEC || c->kind == PROBE_EXTERNAL) {
        sb_printf(err, "the agent does not run %s probes", kind);
        return -1;
    }
    if (get_str(o, "host", &c->host, err) < 0 || get_str(o, "ip", &c->ip, err) < 0 ||
        get_str(o, "path", &c->path, err) < 0 || get_str(o, "bad_word", &c->bad_word, err) < 0 ||
        get_str(o, "valid_contains", &c->valid_contains, err) < 0 ||
        get_str(o, "injected_contains", &c->injected_contains, err) < 0 ||
        get_str(o, "alpn", &c->alpn, err) < 0 || get_str(o, "dns_expect", &c->dns_expect, err) < 0 ||
        get_str(o, "dns_bad", &c->dns_bad, err) < 0)
        return -1;
    if (!c->host && !c->ip) {
        sb_puts(err, "the probe needs \"host\" or \"ip\"");
        return -1;
    }
    if (c->kind == PROBE_DNS && !c->host) {
        sb_puts(err, "the dns probe needs \"host\"");
        return -1;
    }
    if (!c->path)
        c->path = "/";
    port = json_get_int(o, "port", 0);
    timeout = json_get_num(o, "timeout", 5);
    tls = json_get_int(o, "tls_version", 0);
    minb = json_get_int(o, "min_bytes", 0);
    maxb = json_get_int(o, "max_bytes", 4 << 20);
    if (port < 1 || port > 65535) {
        sb_puts(err, "\"port\" must be 1-65535");
        return -1;
    }
    if (!(timeout >= 0.05 && timeout <= AGENT_MAX_TIMEOUT)) {
        sb_printf(err, "\"timeout\" must be 0.05-%g", AGENT_MAX_TIMEOUT);
        return -1;
    }
    if (tls != 0 && tls != 12 && tls != 13) {
        sb_puts(err, "\"tls_version\" must be 12, 13 or 0");
        return -1;
    }
    if (minb < 0 || maxb < 1 || maxb > (int64_t)AGENT_MAX_BYTES || minb > maxb) {
        sb_puts(err, "bad \"min_bytes\" or \"max_bytes\"");
        return -1;
    }
    c->port = (uint16_t)port;
    c->timeout = timeout;
    c->tls_version = (int)tls;
    c->min_bytes = (size_t)minb;
    c->max_bytes = (size_t)maxb;
    c->dns_tcp = json_get_bool(o, "dns_tcp", 0);
    c->dns_aaaa = json_get_bool(o, "dns_aaaa", 0);
    if (get_str(o, "payload", &payload, err) < 0)
        return -1;
    if (payload && probe_parse_payload(payload, &c->payload, &c->payload_len) < 0) {
        sb_puts(err, "bad \"payload\"");
        return -1;
    }
    if (probe_resolve(c, err) < 0) {
        free(c->payload);
        c->payload = NULL;
        return -1;
    }
    return 0;
}

/* ---- the agent ----------------------------------------------------------- */

int agent_handler(void *ctx, const char *cmd, const json_val *req, jw *resp, sbuf *err)
{
    agent_state *st = ctx;
    if (!strcmp(cmd, "hello")) {
        jw_kstr(resp, "version", GENEVA_VERSION);
        jw_kint(resp, "proto", GENEVA_PROTO_VERSION);
        jw_kstr(resp, "os", plat_os_name());
        jw_kstr(resp, "arch", plat_arch_name());
        jw_kuint(resp, "probes_run", st->probes);
        jw_key(resp, "probes");
        jw_arr(resp);
        jw_str(resp, "http");
        jw_str(resp, "tls");
        jw_str(resp, "dns");
        jw_str(resp, "tcp");
        jw_arr_end(resp);
        return 0;
    }
    if (!strcmp(cmd, "probe")) {
        probe_cfg c;
        probe_res r;
        if (agent_probe_parse(json_get(req, "probe"), &c, err) < 0) {
            LOGW("agent", "refused a probe: %s", err->data);
            return -1;
        }
        st->probes++;
        probe_run(&c, &st->ports, &r);
        LOGI("agent", "probe %s %s:%u: %s (%s)", probe_kind_name(c.kind), c.host ? c.host : c.ip,
             (unsigned)c.port, probe_outcome_name(r.outcome), r.detail);
        jw_kstr(resp, "outcome", probe_outcome_name(r.outcome));
        jw_kdbl(resp, "fitness", r.fitness);
        jw_kuint(resp, "bytes", r.bytes);
        jw_kstr(resp, "detail", r.detail);
        free(c.payload);
        return 0;
    }
    sb_puts(err, "unknown command");
    return -1;
}

/* ---- the evaluator's client ---------------------------------------------- */

struct agent_conn {
    char *spec, *token;
    int listen;
    sock_t ls; /* listen mode: kept open, so that the agent can dial in again */
    ctl_conn c;
    int id;
    double wait_s;
    volatile sig_atomic_t *stop;
    char name[96];
};

static int is_stopped(const agent_conn *a) { return a->stop && *a->stop; }

static void drop(agent_conn *a)
{
    if (a->c.s != SOCK_INVALID)
        plat_sock_close(a->c.s);
    a->c.s = SOCK_INVALID;
    sb_reset(&a->c.in);
}

/* Sends req and waits for the answer with its id. Returns the parsed
 * answer (ok or not), or NULL when the connection failed. */
static json_val *call(agent_conn *a, sbuf *req, int id, int timeout_ms, sbuf *err)
{
    sbuf line;
    json_val *v = NULL;
    sb_init(&line);
    if (ctl_send_line(&a->c, req->data) < 0) {
        sb_puts(err, "send failed");
        goto out;
    }
    for (;;) {
        const char *perr = NULL;
        int r = ctl_read_line(&a->c, &line, timeout_ms);
        if (r == 0) {
            sb_printf(err, "no answer in %d s", timeout_ms / 1000);
            break;
        }
        if (r < 0) {
            sb_puts(err, "connection closed");
            break;
        }
        v = json_parse(line.data, &perr);
        if (v && v->type == JSON_OBJ && json_get_int(v, "id", -1) == id)
            break;
        json_free(v); /* not our answer */
        v = NULL;
    }
out:
    sb_free(&line);
    return v;
}

static json_val *simple(agent_conn *a, const char *cmd, const char *token, sbuf *err)
{
    sbuf req;
    jw w;
    json_val *v;
    int id = ++a->id;
    sb_init(&req);
    jw_init(&w, &req);
    jw_obj(&w);
    jw_kint(&w, "id", id);
    jw_kstr(&w, "cmd", cmd);
    if (token)
        jw_kstr(&w, "token", token);
    jw_obj_end(&w);
    v = call(a, &req, id, 10000, err);
    sb_free(&req);
    return v;
}

/* Connects (or accepts) and greets. Returns 0 or -1 with a message. */
static int establish(agent_conn *a, sbuf *err)
{
    json_val *v;
    drop(a);
    if (!a->listen) {
        a->c.s = ctl_connect(a->spec, err);
        if (a->c.s == SOCK_INVALID)
            return -1;
    } else {
        uint64_t end = plat_now_ms() + (uint64_t)(a->wait_s * 1000);
        LOGI("eval", "waiting for the agent on %s", a->spec);
        while (a->c.s == SOCK_INVALID) {
            plat_pollfd p;
            p.fd = a->ls;
            p.events = POLLIN;
            p.revents = 0;
            if (is_stopped(a) || plat_now_ms() >= end) {
                sb_printf(err, "no agent dialed in to %s", a->spec);
                return -1;
            }
            if (plat_poll(&p, 1, 200) > 0)
                a->c.s = accept(a->ls, NULL, NULL);
        }
    }
    if (a->token) {
        v = simple(a, "auth", a->token, err);
        if (!v || !json_get_bool(v, "ok", 0)) {
            if (v)
                sb_printf(err, "the agent refused the token: %s", json_get_str(v, "error", "?"));
            json_free(v);
            drop(a);
            return -1;
        }
        json_free(v);
    }
    v = simple(a, "hello", NULL, err);
    if (!v || !json_get_bool(v, "ok", 0)) {
        if (v)
            sb_printf(err, "the agent did not answer hello: %s", json_get_str(v, "error", "?"));
        json_free(v);
        drop(a);
        return -1;
    }
    if (json_get_int(v, "proto", 0) != GENEVA_PROTO_VERSION) {
        sb_printf(err, "the agent speaks protocol %lld, not %d", (long long)json_get_int(v, "proto", 0),
                  GENEVA_PROTO_VERSION);
        json_free(v);
        drop(a);
        return -1;
    }
    snprintf(a->name, sizeof(a->name), "%s/%s %s", json_get_str(v, "os", "?"), json_get_str(v, "arch", "?"),
             json_get_str(v, "version", "?"));
    json_free(v);
    LOGI("eval", "agent %s connected", a->name);
    return 0;
}

agent_conn *agent_open(const char *spec, int listen, const char *token, double wait_s,
                       volatile sig_atomic_t *stop, sbuf *err)
{
    agent_conn *a = xcalloc(1, sizeof(*a));
    a->spec = xstrdup(spec);
    a->token = token && *token ? xstrdup(token) : NULL;
    a->listen = listen;
    a->ls = SOCK_INVALID;
    a->c.s = SOCK_INVALID;
    sb_init(&a->c.in);
    a->wait_s = wait_s;
    a->stop = stop;
    if (listen && (a->ls = ctl_listen(spec, a->token != NULL, err)) == SOCK_INVALID) {
        agent_close(a);
        return NULL;
    }
    if (establish(a, err) < 0) {
        agent_close(a);
        return NULL;
    }
    return a;
}

static int parse_outcome(const char *s, probe_outcome *o)
{
    for (int i = PO_OK; i <= PO_FAILED; i++)
        if (!strcmp(s, probe_outcome_name((probe_outcome)i))) {
            *o = (probe_outcome)i;
            return 0;
        }
    return -1;
}

int agent_probe(agent_conn *a, const probe_cfg *c, probe_res *r)
{
    int ms = (int)(c->timeout * 4000) + 10000; /* connect, send, a few reads */
    memset(r, 0, sizeof(*r));
    for (int attempt = 0; attempt < 2; attempt++) {
        sbuf req, err;
        jw w;
        json_val *v;
        int id = ++a->id;
        sb_init(&err);
        if (a->c.s == SOCK_INVALID && establish(a, &err) < 0) {
            LOGW("eval", "agent: %s", err.data);
            sb_free(&err);
            continue;
        }
        sb_init(&req);
        jw_init(&w, &req);
        jw_obj(&w);
        jw_kint(&w, "id", id);
        jw_kstr(&w, "cmd", "probe");
        agent_probe_json(c, &w);
        jw_obj_end(&w);
        v = call(a, &req, id, ms, &err);
        sb_free(&req);
        if (!v) {
            LOGW("eval", "agent: %s", err.data);
            sb_free(&err);
            drop(a);
            continue;
        }
        sb_free(&err);
        if (!json_get_bool(v, "ok", 0) || parse_outcome(json_get_str(v, "outcome", ""), &r->outcome) < 0) {
            r->outcome = PO_FAILED;
            snprintf(r->detail, sizeof(r->detail), "agent: %s", json_get_str(v, "error", "bad answer"));
            json_free(v);
            return -1; /* the same request would fail again */
        }
        r->fitness = probe_fitness(r->outcome);
        r->bytes = (size_t)json_get_int(v, "bytes", 0);
        snprintf(r->detail, sizeof(r->detail), "%s", json_get_str(v, "detail", ""));
        json_free(v);
        return 0;
    }
    r->outcome = PO_FAILED;
    snprintf(r->detail, sizeof(r->detail), "the agent is gone");
    return -1;
}

const char *agent_name(const agent_conn *a) { return a->name; }

void agent_close(agent_conn *a)
{
    if (!a)
        return;
    drop(a);
    if (a->ls != SOCK_INVALID)
        plat_sock_close(a->ls);
    sb_free(&a->c.in);
    free(a->spec);
    free(a->token);
    free(a);
}
