/* Control socket: framing, auth, built-ins, handler, event broadcast. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ctl.h"
#include "json.h"
#include "plat.h"
#include "test.h"
#include "util.h"

#ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
#endif

static int handler(void *ctx, const char *cmd, const json_val *req, jw *w, sbuf *err)
{
    int *calls = ctx;
    (*calls)++;
    if (!strcmp(cmd, "echo")) {
        jw_kstr(w, "said", json_get_str(req, "text", ""));
        return 0;
    }
    if (!strcmp(cmd, "failpos")) { /* fields written before a failure reach the error */
        jw_kint(w, "pos", 7);
        sb_puts(err, "bad");
        return -1;
    }
    if (!strcmp(cmd, "set_filter")) {
        jw_kuint(w, "len", strlen(json_get_str(req, "filter", "")));
        return 0;
    }
    sb_puts(err, "unknown command");
    return -1;
}

/* Runs the server side until a full line arrives on s (or 2 s pass). */
static int exchange(ctl *c, sock_t s, const char *send_text, char *line, size_t cap, int *calls)
{
    static char buf[1 << 16];
    static size_t have;
    uint64_t end = plat_now_ms() + 2000;
    if (send_text) {
        send(s, send_text, (int)strlen(send_text), MSG_NOSIGNAL);
        send(s, "\n", 1, MSG_NOSIGNAL);
    }
    while (plat_now_ms() < end) {
        plat_pollfd fds[CTL_MAX_CLIENTS + 2];
        size_t n = ctl_pollfds(c, fds, CTL_MAX_CLIENTS + 1);
        char *nl;
        int r;
        fds[n].fd = s;
        fds[n].events = POLLIN;
        fds[n].revents = 0;
        plat_poll(fds, (unsigned)n + 1, 50);
        ctl_dispatch(c, fds, n, handler, calls);
        if (fds[n].revents & (POLLIN | POLLHUP)) {
            r = (int)recv(s, buf + have, (int)(sizeof(buf) - have - 1), 0);
            if (r <= 0)
                return -1;
            have += (size_t)r;
        }
        buf[have] = 0;
        if ((nl = strchr(buf, '\n')) != NULL) {
            size_t len = (size_t)(nl - buf);
            snprintf(line, cap, "%.*s", (int)len, buf);
            memmove(buf, nl + 1, have - len - 1);
            have -= len + 1;
            return 0;
        }
    }
    return -1;
}

static void test_ctl_tcp(void)
{
    sbuf err, spec;
    ctl *c;
    sock_t s;
    char line[4096];
    int calls = 0;
    t_current = "ctl tcp";
    sb_init(&err);
    sb_init(&spec);
    CHECK(ctl_open("tcp:0.0.0.0:0", NULL, &err) == NULL); /* public without a token */
    sb_reset(&err);
    CHECK(ctl_open("tcp:notanaddress:1", NULL, &err) == NULL);
    sb_reset(&err);
    c = ctl_open("tcp:127.0.0.1:0", "s3cret", &err);
    CHECK(c != NULL);
    if (!c)
        return;
    CHECK(ctl_port(c) > 0);
    sb_printf(&spec, "tcp:127.0.0.1:%d", ctl_port(c));
    s = ctl_connect(spec.data, &err);
    CHECK(s != SOCK_INVALID);

    CHECK_INT(exchange(c, s, "{\"id\":1,\"cmd\":\"ping\"}", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "\"id\":1") && strstr(line, "\"ok\":true"));
    CHECK_INT(exchange(c, s, "{\"id\":2,\"cmd\":\"echo\",\"text\":\"x\"}", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "\"ok\":false") && strstr(line, "not authenticated"));
    CHECK_INT(calls, 0);
    CHECK_INT(exchange(c, s, "{\"id\":\"a\",\"cmd\":\"auth\",\"token\":\"s3cret\"}", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "\"id\":\"a\"") && strstr(line, "\"ok\":true"));
    CHECK_INT(exchange(c, s, "{\"id\":3,\"cmd\":\"echo\",\"text\":\"hi \\\"there\\\"\"}", line, sizeof(line), &calls), 0);
    CHECK_STR(line, "{\"id\":3,\"ok\":true,\"said\":\"hi \\\"there\\\"\"}");
    CHECK_INT(calls, 1);
    CHECK_INT(exchange(c, s, "{\"id\":4,\"cmd\":\"nope\"}", line, sizeof(line), &calls), 0);
    CHECK_STR(line, "{\"id\":4,\"ok\":false,\"error\":\"unknown command\"}");
    CHECK_INT(exchange(c, s, "{\"id\":44,\"cmd\":\"failpos\"}", line, sizeof(line), &calls), 0);
    CHECK_STR(line, "{\"id\":44,\"ok\":false,\"error\":\"bad\",\"pos\":7}");
    calls--;
    CHECK_INT(exchange(c, s, "not json", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "\"ok\":false") != NULL);
    CHECK_INT(exchange(c, s, "{\"id\":5}", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "missing") != NULL);

    /* events reach subscribers only */
    ctl_broadcast("{\"ev\":\"x\"}\n", 11, c);
    CHECK_INT(exchange(c, s, "{\"id\":6,\"cmd\":\"subscribe\"}", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "\"id\":6") != NULL);
    CHECK_INT(ctl_subscribers(c), 1);
    ctl_broadcast("{\"ev\":\"y\"}\n", 11, c);
    CHECK_INT(exchange(c, s, NULL, line, sizeof(line), &calls), 0);
    CHECK_STR(line, "{\"ev\":\"y\"}");
    CHECK_INT(exchange(c, s, "{\"id\":7,\"cmd\":\"unsubscribe\"}", line, sizeof(line), &calls), 0);
    CHECK_INT(ctl_subscribers(c), 0);

    /* a wrong token closes the connection */
    plat_sock_close(s);
    s = ctl_connect(spec.data, &err);
    CHECK_INT(exchange(c, s, "{\"id\":8,\"cmd\":\"auth\",\"token\":\"bad\"}", line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "wrong token") != NULL);
    CHECK_INT(exchange(c, s, "{\"id\":9,\"cmd\":\"ping\"}", line, sizeof(line), &calls), -1);
    plat_sock_close(s);
    ctl_close(c);
    sb_free(&err);
    sb_free(&spec);
}


/* Sends a long line while serving the server, then reads one answer line
 * (only its first bytes are kept). */
static int long_exchange(ctl *c, sock_t s, const char *text, char *line, size_t cap, int *calls)
{
    size_t len = strlen(text), off = 0;
    sbuf in;
    uint64_t end = plat_now_ms() + 5000;
    int rc = -1;
    sb_init(&in);
    plat_sock_nonblock(s, 1);
    while (plat_now_ms() < end) {
        plat_pollfd fds[CTL_MAX_CLIENTS + 2];
        size_t n = ctl_pollfds(c, fds, CTL_MAX_CLIENTS + 1);
        char buf[4096], *nl;
        int r;
        if (off < len) {
            r = (int)send(s, text + off, (int)MIN(len - off, (size_t)16384), MSG_NOSIGNAL);
            if (r > 0)
                off += (size_t)r;
            if (off == len)
                send(s, "\n", 1, MSG_NOSIGNAL);
        }
        fds[n].fd = s;
        fds[n].events = POLLIN;
        fds[n].revents = 0;
        plat_poll(fds, (unsigned)n + 1, 10);
        ctl_dispatch(c, fds, n, handler, calls);
        r = (int)recv(s, buf, sizeof(buf), 0);
        if (r > 0)
            sb_append(&in, buf, (size_t)r);
        else if (r == 0)
            break;
        if (in.len && (nl = memchr(in.data, '\n', in.len)) != NULL) {
            snprintf(line, cap, "%.*s", (int)(nl - in.data), in.data);
            rc = 0;
            break;
        }
    }
    plat_sock_nonblock(s, 0);
    sb_free(&in);
    return rc;
}

static void test_ctl_long_lines(void)
{
    sbuf err, spec, req;
    ctl *c;
    sock_t s;
    char line[4096];
    int calls = 0;
    size_t flen = 300000; /* past 64 KB, within the 1 MB of set_filter */
    t_current = "ctl long lines";
    sb_init(&err);
    sb_init(&spec);
    sb_init(&req);
    c = ctl_open("tcp:127.0.0.1:0", NULL, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    sb_printf(&spec, "tcp:127.0.0.1:%d", ctl_port(c));
    s = ctl_connect(spec.data, &err);

    sb_puts(&req, "{\"id\":1,\"filter\":\"");
    for (size_t i = 0; i < flen; i++)
        sb_putc(&req, 'a');
    sb_puts(&req, "\",\"cmd\":\"set_filter\"}"); /* cmd after the long value */
    CHECK_INT(long_exchange(c, s, req.data, line, sizeof(line), &calls), 0);
    CHECK_STR(line, "{\"id\":1,\"ok\":true,\"len\":300000}");

    /* another command may not be longer than 64 KB */
    sb_reset(&req);
    sb_puts(&req, "{\"id\":2,\"cmd\":\"echo\",\"text\":\"");
    for (size_t i = 0; i < 70000; i++)
        sb_putc(&req, 'b');
    sb_puts(&req, "\"}");
    CHECK_INT(long_exchange(c, s, req.data, line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "\"ok\":false") && strstr(line, "too long"));
    CHECK_INT(calls, 1);
    plat_sock_close(s);

    /* nor set_filter longer than 1 MB */
    s = ctl_connect(spec.data, &err);
    sb_reset(&req);
    sb_puts(&req, "{\"id\":3,\"cmd\":\"set_filter\",\"filter\":\"");
    for (size_t i = 0; i < CTL_MAX_FILTER_LINE + 10; i++)
        sb_putc(&req, 'c');
    sb_puts(&req, "\"}");
    CHECK_INT(long_exchange(c, s, req.data, line, sizeof(line), &calls), 0);
    CHECK(strstr(line, "too long") != NULL);
    CHECK_INT(calls, 1);
    plat_sock_close(s);
    ctl_close(c);
    sb_free(&err);
    sb_free(&spec);
    sb_free(&req);
}

#ifndef _WIN32
static void test_ctl_unix(void)
{
    sbuf err;
    ctl *c, *c2;
    sock_t s;
    char path[64], spec[80], line[512];
    int calls = 0;
    t_current = "ctl unix";
    sb_init(&err);
    snprintf(path, sizeof(path), "/tmp/geneva-test-%d.sock", plat_getpid());
    snprintf(spec, sizeof(spec), "unix:%s", path);
    c = ctl_open(spec, NULL, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    sb_reset(&err);
    c2 = ctl_open(spec, NULL, &err); /* a live socket is not stolen */
    CHECK(c2 == NULL && strstr(err.data, "in use"));
    {
        /* a regular file in the way is not removed */
        char fpath[80], fspec[96];
        FILE *f;
        snprintf(fpath, sizeof(fpath), "%s.file", path);
        snprintf(fspec, sizeof(fspec), "unix:%s", fpath);
        f = fopen(fpath, "w");
        if (f)
            fclose(f);
        sb_reset(&err);
        CHECK(ctl_open(fspec, NULL, &err) == NULL && strstr(err.data, "not a socket"));
        f = fopen(fpath, "r");
        CHECK(f != NULL);
        if (f)
            fclose(f);
        remove(fpath);
    }
    s = ctl_connect(spec, &err);
    CHECK(s != SOCK_INVALID);
    CHECK_INT(exchange(c, s, "{\"id\":1,\"cmd\":\"echo\",\"text\":\"u\"}", line, sizeof(line), &calls), 0);
    CHECK_STR(line, "{\"id\":1,\"ok\":true,\"said\":\"u\"}");
    plat_sock_close(s);
    ctl_close(c);
    CHECK(fopen(path, "r") == NULL); /* removed on close */
    sb_free(&err);
}
#endif

void suite_ctl(void)
{
    test_ctl_tcp();
    test_ctl_long_lines();
#ifndef _WIN32
    test_ctl_unix();
#endif
}
