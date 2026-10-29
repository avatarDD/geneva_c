/*
 * "geneva ctl": command-line client of the control socket.
 *
 *   geneva ctl status
 *   geneva ctl set_strategy strategy='[TCP:flags:PA]-drop-| \/'
 *   geneva ctl subscribe --until exit
 *   geneva ctl --json '{"cmd":"log_level","level":"debug"}'
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ctl.h"
#include "geneva.h"
#include "json.h"
#include "plat.h"
#include "util.h"

#define CTL_DEFAULT "unix:/var/run/geneva.sock"

/* Sends a request and waits for the response with the same id. Events that
 * arrive meanwhile are printed when show_events is set. */
static int request(ctl_conn *c, const char *req, int id, int timeout_ms, sbuf *resp)
{
    if (ctl_send_line(c, req) < 0) {
        fprintf(stderr, "geneva ctl: send failed\n");
        return -1;
    }
    for (;;) {
        const char *perr;
        json_val *v;
        int r = ctl_read_line(c, resp, timeout_ms);
        if (r == 0) {
            fprintf(stderr, "geneva ctl: no answer within %d ms\n", timeout_ms);
            return -1;
        }
        if (r < 0) {
            fprintf(stderr, "geneva ctl: connection closed\n");
            return -1;
        }
        v = json_parse(resp->data, &perr);
        if (v && v->type == JSON_OBJ && json_get(v, "ok") &&
            (!json_get(v, "id") || json_get_int(v, "id", -1) == id)) {
            json_free(v);
            return 0;
        }
        json_free(v); /* an event line: not our answer */
    }
}

static int is_ok(const char *line)
{
    const char *perr;
    json_val *v = json_parse(line, &perr);
    int ok = v && json_get_bool(v, "ok", 0);
    json_free(v);
    return ok;
}

int cmd_ctl(int argc, char **argv)
{
    static const optdef defs[] = {
        {"control", 'c', 1, "ADDR", "control socket (default $GENEVA_CONTROL or " CTL_DEFAULT ")"},
        {"token", 't', 1, "TOKEN", "control token (default $GENEVA_CONTROL_TOKEN)"},
        {"json", 'j', 1, "JSON", "send this request object as is"},
        {"timeout", 0, 1, "SEC", "wait this long for an answer (default 10)"},
        {"until", 0, 1, "EVENT", "subscribe: stop after an event of this type"},
        {"count", 'n', 1, "N", "subscribe: stop after N events"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    const char *addr, *token, *until;
    ctl_conn c = {SOCK_INVALID, {0}};
    sbuf req, resp, e;
    double timeout;
    int64_t count;
    int rc = EXIT_USAGE, tmo, subscribe = 0;
    const char *cmd = NULL;

    sb_init(&req);
    sb_init(&resp);
    sb_init(&e);
    sb_init(&c.in);
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva ctl: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva ctl [options] COMMAND [key=value...]\n"
                  "Talks to \"geneva run --control ADDR\". Commands: status, stats, reset_stats,\n"
                  "set_strategy strategy=..., reload, pause, resume, log_level level=...,\n"
                  "subscribe, stop, ping, version. Prints the JSON answer; exit code 1 if\n"
                  "it is not ok.",
                  defs);
        rc = EXIT_OK;
        goto done;
    }
    addr = arg_str(&a, "control", getenv("GENEVA_CONTROL") ? getenv("GENEVA_CONTROL") : CTL_DEFAULT);
    token = arg_str(&a, "token", getenv("GENEVA_CONTROL_TOKEN"));
    until = arg_str(&a, "until", NULL);
    if (arg_dbl(&a, "timeout", 10, 0.001, 86400, &timeout) < 0 ||
        arg_int(&a, "count", 0, 0, INT64_MAX, &count) < 0)
        goto done;
    tmo = (int)(timeout * 1000);

    if (arg_has(&a, "json")) {
        const char *perr;
        json_val *v = json_parse(arg_str(&a, "json", ""), &perr);
        if (!v || v->type != JSON_OBJ || !json_get_str(v, "cmd", NULL) || a.npos) {
            fprintf(stderr, "geneva ctl: --json needs an object with \"cmd\" (and no other arguments)\n");
            json_free(v);
            goto done;
        }
        subscribe = !strcmp(json_get_str(v, "cmd", ""), "subscribe");
        /* re-serialize with our id so the answer can be matched */
        {
            jw w;
            jw_init(&w, &req);
            jw_obj(&w);
            jw_kint(&w, "id", 2);
            for (size_t i = 0; i < v->n; i++) {
                const json_val *it = v->items[i];
                if (!strcmp(v->keys[i], "id"))
                    continue;
                jw_key(&w, v->keys[i]);
                switch (it->type) {
                case JSON_STR: jw_str(&w, it->str); break;
                case JSON_NUM: jw_dbl(&w, it->num); break;
                case JSON_BOOL: jw_bool(&w, it->boolean); break;
                case JSON_NULL: jw_null(&w); break;
                default:
                    fprintf(stderr, "geneva ctl: nested values are not supported in --json\n");
                    json_free(v);
                    goto done;
                }
            }
            jw_obj_end(&w);
        }
        json_free(v);
    } else {
        jw w;
        if (!a.npos) {
            fprintf(stderr, "geneva ctl: need a command (see --help)\n");
            goto done;
        }
        cmd = a.pos[0];
        subscribe = !strcmp(cmd, "subscribe");
        jw_init(&w, &req);
        jw_obj(&w);
        jw_kint(&w, "id", 2);
        jw_kstr(&w, "cmd", cmd);
        for (int i = 1; i < a.npos; i++) {
            const char *eq = strchr(a.pos[i], '=');
            char *k;
            if (!eq || eq == a.pos[i]) {
                fprintf(stderr, "geneva ctl: expected key=value, got \"%s\"\n", a.pos[i]);
                goto done;
            }
            k = xstrndup(a.pos[i], (size_t)(eq - a.pos[i]));
            jw_kstr(&w, k, eq + 1);
            free(k);
        }
        jw_obj_end(&w);
    }

    c.s = ctl_connect(addr, &e);
    if (c.s == SOCK_INVALID) {
        fprintf(stderr, "geneva ctl: %s\n", e.data);
        rc = EXIT_IO;
        goto done;
    }
    if (token && *token) {
        sbuf auth;
        jw w;
        sb_init(&auth);
        jw_init(&w, &auth);
        jw_obj(&w);
        jw_kint(&w, "id", 1);
        jw_kstr(&w, "cmd", "auth");
        jw_kstr(&w, "token", token);
        jw_obj_end(&w);
        if (request(&c, auth.data, 1, tmo, &resp) < 0) {
            sb_free(&auth);
            rc = EXIT_IO;
            goto done;
        }
        sb_free(&auth);
        if (!is_ok(resp.data)) {
            printf("%s\n", resp.data);
            rc = EXIT_FAIL;
            goto done;
        }
    }
    if (request(&c, req.data, 2, tmo, &resp) < 0) {
        rc = EXIT_IO;
        goto done;
    }
    printf("%s\n", resp.data);
    fflush(stdout);
    if (!is_ok(resp.data)) {
        rc = EXIT_FAIL;
        goto done;
    }
    rc = EXIT_OK;
    if (subscribe) {
        int64_t seen = 0;
        int idle = arg_has(&a, "timeout") ? tmo : -1;
        for (;;) {
            int r = ctl_read_line(&c, &resp, idle);
            if (r <= 0)
                break; /* the engine exited, a signal, or --timeout without events */
            printf("%s\n", resp.data);
            fflush(stdout);
            seen++;
            if (count && seen >= count)
                break;
            if (until) {
                const char *perr;
                json_val *v = json_parse(resp.data, &perr);
                int hit = v && !strcmp(json_get_str(v, "ev", ""), until);
                json_free(v);
                if (hit)
                    break;
            }
        }
    }
done:
    if (c.s != SOCK_INVALID)
        plat_sock_close(c.s);
    sb_free(&c.in);
    sb_free(&req);
    sb_free(&resp);
    sb_free(&e);
    args_free(&a);
    return rc;
}
