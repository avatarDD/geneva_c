#include "ctl.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "log.h"

#ifndef _WIN32
#  include <netdb.h>
#  include <sys/stat.h>
#  include <sys/un.h>
#endif

#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

typedef struct {
    sock_t s;
    sbuf in, out;
    int authed;
    int subscribed;
    int closing;     /* close once out is flushed */
    uint64_t dropped; /* events lost to a full output buffer */
} client;

struct ctl {
    sock_t ls;
    int port;
    char *unix_path;
    char *token;
    client cl[CTL_MAX_CLIENTS];
    int ncl;
    int nsub;
};

/* ---- address parsing ----------------------------------------------------- */

typedef struct {
    int is_unix;
    char path[108];
    struct sockaddr_storage ss;
    socklen_t sslen;
    int loopback;
} ctl_addr;

static int parse_spec(const char *spec, ctl_addr *a, sbuf *err)
{
    memset(a, 0, sizeof(*a));
    if (str_starts(spec, "unix:")) {
#ifdef _WIN32
        sb_puts(err, "unix sockets are not supported on Windows, use tcp:PORT");
        return -1;
#else
        const char *p = spec + 5;
        if (!*p || strlen(p) >= sizeof(((struct sockaddr_un *)0)->sun_path)) {
            sb_printf(err, "bad unix socket path \"%s\"", p);
            return -1;
        }
        a->is_unix = 1;
        snprintf(a->path, sizeof(a->path), "%s", p);
        a->loopback = 1;
        return 0;
#endif
    }
    if (str_starts(spec, "tcp:")) {
        const char *p = spec + 4, *colon;
        char host[64] = "127.0.0.1";
        int64_t port;
        if (*p == '[') { /* [v6]:port */
            const char *end = strchr(p, ']');
            if (!end || end[1] != ':' || (size_t)(end - p - 1) >= sizeof(host))
                goto bad;
            memcpy(host, p + 1, (size_t)(end - p - 1));
            host[end - p - 1] = 0;
            p = end + 2;
        } else if ((colon = strrchr(p, ':')) != NULL) {
            if ((size_t)(colon - p) >= sizeof(host))
                goto bad;
            memcpy(host, p, (size_t)(colon - p));
            host[colon - p] = 0;
            p = colon + 1;
        }
        if (parse_i64(p, &port) < 0 || port < 0 || port > 65535)
            goto bad;
        if (strchr(host, ':')) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&a->ss;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons((uint16_t)port);
            if (inet_pton(AF_INET6, host, &s6->sin6_addr) != 1)
                goto bad;
            a->sslen = sizeof(*s6);
            a->loopback = !strcmp(host, "::1");
        } else {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&a->ss;
            s4->sin_family = AF_INET;
            s4->sin_port = htons((uint16_t)port);
            if (inet_pton(AF_INET, host, &s4->sin_addr) != 1)
                goto bad;
            a->sslen = sizeof(*s4);
            a->loopback = (ntohl(s4->sin_addr.s_addr) >> 24) == 127;
        }
        return 0;
    }
bad:
    sb_printf(err, "bad control address \"%s\" (unix:/path, tcp:PORT or tcp:HOST:PORT)", spec);
    return -1;
}

/* ---- server -------------------------------------------------------------- */

ctl *ctl_open(const char *spec, const char *token, sbuf *err)
{
    ctl_addr a;
    ctl *c;
    sock_t s;
    if (parse_spec(spec, &a, err) < 0)
        return NULL;
    if (!a.loopback && (!token || !*token)) {
        sb_puts(err, "a control socket on a non-loopback address needs --control-token");
        return NULL;
    }
#ifndef _WIN32
    if (a.is_unix) {
        struct sockaddr_un su;
        struct stat st;
        mode_t old;
        /* never remove something that is not a socket (a typo in the path) */
        if (lstat(a.path, &st) == 0 && !S_ISSOCK(st.st_mode)) {
            sb_printf(err, "%s exists and is not a socket", a.path);
            return NULL;
        }
        memset(&su, 0, sizeof(su));
        su.sun_family = AF_UNIX;
        memcpy(su.sun_path, a.path, strlen(a.path));
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s == SOCK_INVALID) {
            sb_printf(err, "control socket: %s", strerror(errno));
            return NULL;
        }
        /* a socket file left by a killed instance: remove it if nobody listens */
        if (connect(s, (struct sockaddr *)&su, sizeof(su)) == 0) {
            close(s);
            sb_printf(err, "%s is in use by another instance", a.path);
            return NULL;
        }
        close(s);
        unlink(a.path);
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        old = umask(077); /* only the owner (root) may connect */
        if (s == SOCK_INVALID || bind(s, (struct sockaddr *)&su, sizeof(su)) < 0) {
            umask(old);
            sb_printf(err, "control socket %s: %s", a.path, strerror(errno));
            if (s != SOCK_INVALID)
                close(s);
            return NULL;
        }
        umask(old);
    } else
#endif
    {
        int one = 1;
        s = socket(a.ss.ss_family, SOCK_STREAM, 0);
        if (s == SOCK_INVALID) {
            sb_printf(err, "control socket: %s", plat_sock_strerror(plat_sock_err()));
            return NULL;
        }
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, sizeof(one));
        if (bind(s, (struct sockaddr *)&a.ss, a.sslen) < 0) {
            sb_printf(err, "control socket %s: %s", spec, plat_sock_strerror(plat_sock_err()));
            plat_sock_close(s);
            return NULL;
        }
    }
    if (listen(s, 8) < 0 || plat_sock_nonblock(s, 1) < 0) {
        sb_printf(err, "control socket %s: %s", spec, plat_sock_strerror(plat_sock_err()));
        plat_sock_close(s);
        if (a.is_unix)
            remove(a.path);
        return NULL;
    }
    c = xcalloc(1, sizeof(*c));
    c->ls = s;
    if (a.is_unix) {
        c->unix_path = xstrdup(a.path);
    } else {
        struct sockaddr_storage ss;
        socklen_t len = sizeof(ss);
        if (getsockname(s, (struct sockaddr *)&ss, &len) == 0)
            c->port = ntohs(ss.ss_family == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port
                                                     : ((struct sockaddr_in *)&ss)->sin_port);
    }
    if (token && *token)
        c->token = xstrdup(token);
    return c;
}

int ctl_port(const ctl *c) { return c->port; }
int ctl_subscribers(const ctl *c) { return c ? c->nsub : 0; }

static void drop_client(ctl *c, int i)
{
    client *k = &c->cl[i];
    if (k->subscribed)
        c->nsub--;
    plat_sock_close(k->s);
    sb_free(&k->in);
    sb_free(&k->out);
    c->cl[i] = c->cl[--c->ncl];
}

void ctl_close(ctl *c)
{
    if (!c)
        return;
    while (c->ncl)
        drop_client(c, c->ncl - 1);
    plat_sock_close(c->ls);
    if (c->unix_path)
        remove(c->unix_path);
    free(c->unix_path);
    free(c->token);
    free(c);
}

size_t ctl_pollfds(ctl *c, plat_pollfd *fds, size_t max)
{
    size_t n = 0;
    if (!c || !max)
        return 0;
    fds[n].fd = c->ls;
    fds[n].events = POLLIN;
    fds[n++].revents = 0;
    for (int i = 0; i < c->ncl && n < max; i++, n++) {
        fds[n].fd = c->cl[i].s;
        fds[n].events = (short)(POLLIN | (c->cl[i].out.len ? POLLOUT : 0));
        fds[n].revents = 0;
    }
    return n;
}

/* Writes as much pending output as the socket takes. Returns -1 when the
 * client is gone. */
static int flush(client *k)
{
    size_t off = 0;
    while (off < k->out.len) {
        int r = (int)send(k->s, k->out.data + off, (int)MIN(k->out.len - off, (size_t)65536),
                          MSG_NOSIGNAL);
        if (r < 0) {
            int e = plat_sock_err();
            if (plat_sock_would_block(e))
                break;
            if (e == EINTR)
                continue;
            return -1;
        }
        off += (size_t)r;
    }
    if (off) {
        memmove(k->out.data, k->out.data + off, k->out.len - off);
        k->out.len -= off;
        k->out.data[k->out.len] = 0;
    }
    return 0;
}

static void queue(client *k, const char *data, size_t len)
{
    sb_append(&k->out, data, len);
}

void ctl_broadcast(const char *line, size_t len, void *arg)
{
    ctl *c = arg;
    for (int i = 0; i < c->ncl; i++) {
        client *k = &c->cl[i];
        if (!k->subscribed || k->closing)
            continue;
        if (k->out.len + len > CTL_MAX_QUEUED) {
            k->dropped++; /* a slow reader loses events, not the engine */
            continue;
        }
        if (k->dropped) {
            sbuf note;
            sb_init(&note);
            sb_printf(&note, "{\"ts\":%llu,\"ev\":\"dropped\",\"count\":%llu}\n",
                      (unsigned long long)plat_wall_ms(), (unsigned long long)k->dropped);
            queue(k, note.data, note.len);
            sb_free(&note);
            k->dropped = 0;
        }
        queue(k, line, len);
        flush(k); /* errors surface on the next poll */
    }
}

static int token_ok(const char *want, const char *got)
{
    size_t n = strlen(want), m = got ? strlen(got) : 0;
    unsigned diff = (unsigned)(n ^ m);
    for (size_t i = 0; i < n; i++)
        diff |= (unsigned)(want[i] ^ (i < m ? got[i] : 0));
    return diff == 0;
}

static void respond_error(client *k, const json_val *id, const char *msg)
{
    sbuf sb;
    jw w;
    sb_init(&sb);
    jw_init(&w, &sb);
    jw_obj(&w);
    if (id && (id->type == JSON_NUM || id->type == JSON_STR)) {
        jw_key(&w, "id");
        if (id->type == JSON_NUM)
            jw_dbl(&w, id->num);
        else
            jw_str(&w, id->str);
    }
    jw_kbool(&w, "ok", 0);
    jw_kstr(&w, "error", msg);
    jw_obj_end(&w);
    sb_putc(&sb, '\n');
    queue(k, sb.data, sb.len);
    sb_free(&sb);
}

static void handle_line(ctl *c, client *k, const char *line, ctl_handler h, void *ctx)
{
    const char *perr = NULL, *cmd;
    json_val *req = json_parse(line, &perr);
    const json_val *id;
    sbuf sb, err;
    jw w;
    int rc = 0;

    if (!req || req->type != JSON_OBJ) {
        respond_error(k, NULL, perr ? perr : "request must be a JSON object");
        json_free(req);
        return;
    }
    id = json_get(req, "id");
    cmd = json_get_str(req, "cmd", NULL);
    if (!cmd) {
        respond_error(k, id, "missing \"cmd\"");
        json_free(req);
        return;
    }
    if (c->token && !k->authed && strcmp(cmd, "auth") && strcmp(cmd, "ping")) {
        respond_error(k, id, "not authenticated (send auth with the token first)");
        json_free(req);
        return;
    }
    sb_init(&sb);
    sb_init(&err);
    jw_init(&w, &sb);
    jw_obj(&w);
    if (id && (id->type == JSON_NUM || id->type == JSON_STR)) {
        jw_key(&w, "id");
        if (id->type == JSON_NUM)
            jw_dbl(&w, id->num);
        else
            jw_str(&w, id->str);
    }
    jw_kbool(&w, "ok", 1);
    if (!strcmp(cmd, "auth")) {
        if (!c->token || token_ok(c->token, json_get_str(req, "token", NULL)))
            k->authed = 1;
        else {
            sb_puts(&err, "wrong token");
            rc = -1;
            k->closing = 1;
        }
    } else if (!strcmp(cmd, "ping")) {
        jw_kuint(&w, "ts", plat_wall_ms());
    } else if (!strcmp(cmd, "version")) {
        jw_kstr(&w, "version", GENEVA_VERSION);
        jw_kint(&w, "proto", GENEVA_PROTO_VERSION);
    } else if (!strcmp(cmd, "subscribe")) {
        if (!k->subscribed)
            c->nsub++;
        k->subscribed = 1;
    } else if (!strcmp(cmd, "unsubscribe")) {
        if (k->subscribed)
            c->nsub--;
        k->subscribed = 0;
    } else if (h) {
        rc = h(ctx, cmd, req, &w, &err);
    } else {
        sb_puts(&err, "unknown command");
        rc = -1;
    }
    if (rc < 0) {
        respond_error(k, id, err.len ? err.data : "failed");
    } else {
        jw_obj_end(&w);
        sb_putc(&sb, '\n');
        queue(k, sb.data, sb.len);
    }
    sb_free(&sb);
    sb_free(&err);
    json_free(req);
}

static void accept_clients(ctl *c)
{
    for (;;) {
        sock_t s = accept(c->ls, NULL, NULL);
        client *k;
        if (s == SOCK_INVALID)
            return;
        if (c->ncl == CTL_MAX_CLIENTS) {
            static const char busy[] = "{\"ok\":false,\"error\":\"too many clients\"}\n";
            send(s, busy, sizeof(busy) - 1, MSG_NOSIGNAL);
            plat_sock_close(s);
            continue;
        }
        plat_sock_nonblock(s, 1);
        k = &c->cl[c->ncl++];
        memset(k, 0, sizeof(*k));
        k->s = s;
        sb_init(&k->in);
        sb_init(&k->out);
        k->authed = c->token == NULL;
    }
}

/* Reads and handles complete lines. Returns -1 when the client is gone. */
static int read_client(ctl *c, client *k, ctl_handler h, void *ctx)
{
    char buf[4096];
    for (;;) {
        int r = (int)recv(k->s, buf, sizeof(buf), 0);
        char *nl;
        if (r == 0)
            return -1;
        if (r < 0) {
            int e = plat_sock_err();
            if (plat_sock_would_block(e))
                break;
            if (e == EINTR)
                continue;
            return -1;
        }
        sb_append(&k->in, buf, (size_t)r);
        while (k->in.len && (nl = memchr(k->in.data, '\n', k->in.len)) != NULL) {
            size_t n = (size_t)(nl - k->in.data);
            *nl = 0;
            if (n && nl[-1] == '\r')
                nl[-1] = 0;
            if (k->in.data[0] && !k->closing)
                handle_line(c, k, k->in.data, h, ctx);
            memmove(k->in.data, nl + 1, k->in.len - n - 1);
            k->in.len -= n + 1;
            k->in.data[k->in.len] = 0;
        }
        if (k->in.len > CTL_MAX_LINE) {
            respond_error(k, NULL, "request line too long");
            k->closing = 1;
            sb_reset(&k->in);
        }
    }
    return 0;
}

void ctl_dispatch(ctl *c, const plat_pollfd *fds, size_t n, ctl_handler h, void *ctx)
{
    if (!c || !n)
        return;
    /* clients first: accepting reorders nothing, dropping does */
    for (size_t j = n; j-- > 1;) {
        int i;
        for (i = 0; i < c->ncl && c->cl[i].s != fds[j].fd; i++)
            ;
        if (i == c->ncl || !fds[j].revents)
            continue;
        if ((fds[j].revents & (POLLIN | POLLHUP | POLLERR)) && read_client(c, &c->cl[i], h, ctx) < 0) {
            drop_client(c, i);
            continue;
        }
        if (flush(&c->cl[i]) < 0 || (c->cl[i].closing && !c->cl[i].out.len))
            drop_client(c, i);
    }
    if (fds[0].revents & POLLIN)
        accept_clients(c);
}

/* ---- client -------------------------------------------------------------- */

sock_t ctl_connect(const char *spec, sbuf *err)
{
    ctl_addr a;
    sock_t s;
    if (parse_spec(spec, &a, err) < 0)
        return SOCK_INVALID;
#ifndef _WIN32
    if (a.is_unix) {
        struct sockaddr_un su;
        memset(&su, 0, sizeof(su));
        su.sun_family = AF_UNIX;
        memcpy(su.sun_path, a.path, strlen(a.path));
        s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s == SOCK_INVALID || connect(s, (struct sockaddr *)&su, sizeof(su)) < 0) {
            sb_printf(err, "cannot connect to %s: %s", a.path, strerror(errno));
            if (s != SOCK_INVALID)
                close(s);
            return SOCK_INVALID;
        }
        return s;
    }
#endif
    s = socket(a.ss.ss_family, SOCK_STREAM, 0);
    if (s == SOCK_INVALID || connect(s, (struct sockaddr *)&a.ss, a.sslen) < 0) {
        sb_printf(err, "cannot connect to %s: %s", spec, plat_sock_strerror(plat_sock_err()));
        if (s != SOCK_INVALID)
            plat_sock_close(s);
        return SOCK_INVALID;
    }
    return s;
}
