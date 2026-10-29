/*
 * Probes (see probe.h): HTTP, TLS, DNS, raw TCP and external commands, with
 * nothing but sockets, so that they run on a router as they do on a PC.
 */
#include "probe.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#  include <fcntl.h>
#  include <netdb.h>
#  include <signal.h>
#  include <sys/wait.h>
#endif

#include "log.h"

#ifdef MSG_NOSIGNAL
#  define SEND_FLAGS MSG_NOSIGNAL
#else
#  define SEND_FLAGS 0
#endif

#define KEEP_MAX (256 * 1024) /* received bytes kept for the "contains" checks */

#ifdef _WIN32
#  define E_RESET(e)                                                                              \
      ((e) == WSAECONNRESET || (e) == WSAECONNREFUSED || (e) == WSAECONNABORTED ||                \
       (e) == WSAEHOSTUNREACH || (e) == WSAENETUNREACH || (e) == WSAENETRESET)
#  define E_ADDRBUSY(e) ((e) == WSAEADDRINUSE || (e) == WSAEADDRNOTAVAIL)
#else
#  define E_RESET(e)                                                                              \
      ((e) == ECONNRESET || (e) == ECONNREFUSED || (e) == ECONNABORTED || (e) == EHOSTUNREACH ||   \
       (e) == ENETUNREACH || (e) == EPIPE || (e) == ENETRESET)
#  define E_ADDRBUSY(e) ((e) == EADDRINUSE || (e) == EADDRNOTAVAIL)
#endif

static const struct {
    const char *name;
    double fitness;
} outcomes[] = {
    [PO_OK] = {"ok", 400},
    [PO_RESET] = {"reset", -360},
    [PO_INJECTED] = {"injected", -360},
    [PO_CONN_TIMEOUT] = {"connect_timeout", -400},
    [PO_TIMEOUT] = {"timeout", -480},
    [PO_BROKEN] = {"broken", -480},
    [PO_FAILED] = {"failed", -400},
};

const char *probe_outcome_name(probe_outcome o) { return outcomes[o].name; }
double probe_fitness(probe_outcome o) { return outcomes[o].fitness; }

static const char *const kind_names[] = {"http", "tls", "dns", "tcp", "exec", "external"};

const char *probe_kind_name(probe_kind k) { return kind_names[k]; }

int probe_kind_parse(const char *s, probe_kind *out)
{
    for (size_t i = 0; i < ARRAY_LEN(kind_names); i++)
        if (!strcmp(s, kind_names[i])) {
            *out = (probe_kind)i;
            return 0;
        }
    return -1;
}

static void set_res(probe_res *r, probe_outcome o, const char *fmt, ...) PRINTF_LIKE(3, 4);

static void set_res(probe_res *r, probe_outcome o, const char *fmt, ...)
{
    va_list ap;
    r->outcome = o;
    r->fitness = probe_fitness(o);
    va_start(ap, fmt);
    vsnprintf(r->detail, sizeof(r->detail), fmt, ap);
    va_end(ap);
}

/* ---- addresses ----------------------------------------------------------- */

int probe_resolve(probe_cfg *c, sbuf *err)
{
    const char *name = c->ip ? c->ip : c->host;
    struct addrinfo hints, *ai = NULL;
    char port[8];
    int rc;
    /* a command resolves the name itself (maybe past a DNS block) */
    if ((c->kind == PROBE_EXEC || c->kind == PROBE_EXTERNAL) && !c->ip)
        return 0;
    if (!name) {
        sb_puts(err, "need --host or --ip");
        return -1;
    }
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port, sizeof(port), "%u", (unsigned)c->port);
    rc = getaddrinfo(name, port, &hints, &ai);
    if (rc || !ai) {
        sb_printf(err, "cannot resolve %s: %s", name, rc ? gai_strerror(rc) : "no address");
        return -1;
    }
    memcpy(&c->addr, ai->ai_addr, ai->ai_addrlen);
    c->addrlen = (int)ai->ai_addrlen;
    freeaddrinfo(ai);
    return 0;
}

static void addr_text(const probe_cfg *c, char *buf, size_t cap)
{
    const void *a = c->addr.ss_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)&c->addr)->sin6_addr
                                                  : (const void *)&((const struct sockaddr_in *)&c->addr)->sin_addr;
    if (!c->addrlen || !inet_ntop(c->addr.ss_family, a, buf, (socklen_t)cap))
        snprintf(buf, cap, "%s", c->ip ? c->ip : "");
}

/* ---- sockets ------------------------------------------------------------- */

/* Waits until s is readable (or writable). 1 ready, 0 timeout, -1 error. */
static int wait_sock(sock_t s, int for_write, int ms)
{
#ifdef _WIN32
    fd_set rs, ws, es;
    struct timeval tv;
    FD_ZERO(&rs);
    FD_ZERO(&ws);
    FD_ZERO(&es);
    if (for_write)
        FD_SET(s, &ws);
    else
        FD_SET(s, &rs);
    FD_SET(s, &es); /* a failed connect shows up here */
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &rs, &ws, &es, &tv) < 0 ? -1 : (FD_ISSET(s, &rs) || FD_ISSET(s, &ws) || FD_ISSET(s, &es));
#else
    struct pollfd p;
    uint64_t end = plat_now_ms() + (uint64_t)(ms > 0 ? ms : 0);
    for (;;) {
        int r, left = (int)(end > plat_now_ms() ? end - plat_now_ms() : 0);
        p.fd = s;
        p.events = for_write ? POLLOUT : POLLIN;
        p.revents = 0;
        r = poll(&p, 1, left);
        if (r >= 0)
            return r > 0;
        if (errno != EINTR)
            return -1;
    }
#endif
}

/* A socket bound to the next free port of the block. */
static sock_t bind_next(const probe_cfg *c, probe_ports *lp, int type, int *err)
{
    unsigned span = lp->lo ? (unsigned)(lp->hi - lp->lo) + 1 : 1;
    unsigned tries = MIN(span, 64u);
    for (unsigned i = 0; i < tries; i++) {
        struct sockaddr_storage la;
        uint16_t port;
        sock_t s = socket(c->addr.ss_family, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
        if (s == SOCK_INVALID) {
            *err = plat_sock_err();
            return SOCK_INVALID;
        }
        if (!lp->lo)
            return s;
        port = (uint16_t)(lp->lo + lp->next++ % span);
        memset(&la, 0, sizeof(la));
        la.ss_family = c->addr.ss_family;
        if (la.ss_family == AF_INET6)
            ((struct sockaddr_in6 *)&la)->sin6_port = htons(port);
        else
            ((struct sockaddr_in *)&la)->sin_port = htons(port);
        if (!bind(s, (struct sockaddr *)&la,
                  la.ss_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)))
            return s;
        *err = plat_sock_err();
        plat_sock_close(s);
        if (!E_ADDRBUSY(*err))
            return SOCK_INVALID;
    }
    return SOCK_INVALID;
}

static int ms_of(double secs) { return (int)(secs * 1000.0 + 0.5); }

/* Connects a TCP socket from the block. Returns the socket, or SOCK_INVALID
 * with the outcome in r. */
static sock_t tcp_connect(const probe_cfg *c, probe_ports *lp, probe_res *r)
{
    for (int attempt = 0; attempt < 8; attempt++) {
        int err = 0, w;
        sock_t s = bind_next(c, lp, SOCK_STREAM, &err);
        if (s == SOCK_INVALID) {
            set_res(r, PO_FAILED, "no local port: %s", plat_sock_strerror(err));
            return SOCK_INVALID;
        }
        plat_sock_nonblock(s, 1);
        if (!connect(s, (const struct sockaddr *)&c->addr, (socklen_t)c->addrlen))
            return s;
        err = plat_sock_err();
        if (!plat_sock_in_progress(err)) {
            plat_sock_close(s);
            if (E_ADDRBUSY(err))
                continue;
            set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "connect: %s", plat_sock_strerror(err));
            return SOCK_INVALID;
        }
        w = wait_sock(s, 1, ms_of(c->timeout));
        if (w <= 0) {
            plat_sock_close(s);
            set_res(r, PO_CONN_TIMEOUT, "no connection in %g s", c->timeout);
            return SOCK_INVALID;
        }
        {
            int soerr = 0;
            socklen_t sl = sizeof(soerr);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl) < 0)
                soerr = plat_sock_err();
            if (!soerr)
                return s;
            plat_sock_close(s);
            if (E_ADDRBUSY(soerr))
                continue;
            set_res(r, E_RESET(soerr) ? PO_RESET : PO_FAILED, "connect: %s", plat_sock_strerror(soerr));
            return SOCK_INVALID;
        }
    }
    set_res(r, PO_FAILED, "no free local port");
    return SOCK_INVALID;
}

/* Sends everything. 0, or -1 with the outcome in r. */
static int send_all(sock_t s, const void *data, size_t n, double timeout, probe_res *r)
{
    const char *p = data;
    while (n) {
        int k = (int)send(s, p, (int)MIN(n, (size_t)65536), SEND_FLAGS), err;
        if (k > 0) {
            p += k;
            n -= (size_t)k;
            continue;
        }
        err = plat_sock_err();
        if (k < 0 && plat_sock_would_block(err)) {
            if (wait_sock(s, 1, ms_of(timeout)) <= 0) {
                set_res(r, PO_TIMEOUT, "send timed out");
                return -1;
            }
            continue;
        }
        set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "send: %s", plat_sock_strerror(err));
        return -1;
    }
    return 0;
}

/* >0 bytes, 0 end of stream, -1 error (*err), -2 nothing within the timeout. */
static int recv_wait(sock_t s, void *buf, size_t cap, double timeout, int *err)
{
    for (;;) {
        int k = (int)recv(s, (char *)buf, (int)cap, 0);
        if (k >= 0)
            return k;
        *err = plat_sock_err();
        if (!plat_sock_would_block(*err))
            return -1;
        k = wait_sock(s, 0, ms_of(timeout));
        if (k == 0)
            return -2;
        if (k < 0) {
            *err = plat_sock_err();
            return -1;
        }
    }
}

static void keep(sbuf *b, const void *p, size_t n)
{
    if (b->len < KEEP_MAX)
        sb_append(b, p, MIN(n, KEEP_MAX - b->len));
}

static int contains(const sbuf *b, const char *needle)
{
    size_t n = strlen(needle);
    if (!n || n > b->len)
        return n == 0;
    for (size_t i = 0; i + n <= b->len; i++)
        if (!memcmp(b->data + i, needle, n))
            return 1;
    return 0;
}

/* ---- http ---------------------------------------------------------------- */

typedef struct {
    int hdr_done, status, chunked, nobody;
    int64_t clen;
    size_t body;      /* body bytes so far */
    char tail[8];     /* last bytes of the stream (chunked end) */
} http_state;

static const char *find_header(const char *hdr, size_t n, const char *name)
{
    size_t ln = strlen(name);
    for (size_t i = 0; i + ln < n; i++)
        if ((i == 0 || hdr[i - 1] == '\n') && str_ieqn(hdr + i, name, ln) && hdr[i + ln] == ':')
            return hdr + i + ln + 1;
    return NULL;
}

static void http_headers(http_state *h, const sbuf *b, size_t hdr_len)
{
    const char *v;
    h->hdr_done = 1;
    h->clen = -1;
    if (b->len >= 12 && !memcmp(b->data, "HTTP/", 5)) {
        const char *sp = memchr(b->data, ' ', MIN(b->len, (size_t)16));
        if (sp)
            h->status = atoi(sp + 1);
    }
    h->nobody = h->status == 204 || h->status == 304 || (h->status >= 100 && h->status < 200);
    if ((v = find_header(b->data, hdr_len, "content-length")) != NULL) {
        while (*v == ' ' || *v == '\t')
            v++;
        h->clen = strtoll(v, NULL, 10);
    }
    if ((v = find_header(b->data, hdr_len, "transfer-encoding")) != NULL) {
        const char *eol = memchr(v, '\n', hdr_len - (size_t)(v - b->data));
        for (const char *q = v; eol && q + 7 <= eol; q++)
            if (str_ieqn(q, "chunked", 7))
                h->chunked = 1;
    }
}

static int http_complete(const http_state *h)
{
    if (!h->hdr_done)
        return 0;
    if (h->nobody)
        return 1;
    if (h->chunked)
        return !memcmp(h->tail + 3, "0\r\n\r\n", 5);
    return h->clen >= 0 && (int64_t)h->body >= h->clen;
}

/* Reads an HTTP response (http = 1) or any reply (tcp). */
static void read_reply(const probe_cfg *c, sock_t s, int http, probe_res *r)
{
    sbuf b;
    http_state h;
    uint8_t buf[16384];
    size_t total = 0, max = c->max_bytes ? c->max_bytes : 4u << 20;
    int done = 0, err = 0, eof = 0, timed_out = 0, reset = 0;

    sb_init(&b);
    memset(&h, 0, sizeof(h));
    while (!done) {
        int k = recv_wait(s, buf, sizeof(buf), c->timeout, &err);
        if (k == -2) {
            timed_out = 1;
            break;
        }
        if (k < 0) {
            reset = 1;
            break;
        }
        if (k == 0) {
            eof = 1;
            break;
        }
        keep(&b, buf, (size_t)k);
        total += (size_t)k;
        if (http) {
            size_t sh = MIN((size_t)k, sizeof(h.tail));
            memmove(h.tail, h.tail + sh, sizeof(h.tail) - sh);
            memcpy(h.tail + sizeof(h.tail) - sh, buf + (size_t)k - sh, sh);
            if (!h.hdr_done) {
                const char *end = NULL;
                for (size_t i = 0; i + 4 <= b.len; i++)
                    if (!memcmp(b.data + i, "\r\n\r\n", 4)) {
                        end = b.data + i + 4;
                        break;
                    }
                if (end) {
                    http_headers(&h, &b, (size_t)(end - b.data));
                    h.body = total - (size_t)(end - b.data);
                }
            } else {
                h.body += (size_t)k;
            }
            done = http_complete(&h);
        } else if (c->valid_contains || c->min_bytes) {
            done = (!c->valid_contains || contains(&b, c->valid_contains)) && total >= c->min_bytes;
        }
        if (total >= max)
            done = 1;
    }
    r->bytes = total;
    if (c->injected_contains && contains(&b, c->injected_contains)) {
        set_res(r, PO_INJECTED, "the answer contains \"%s\"", c->injected_contains);
    } else if (!total) {
        if (timed_out)
            set_res(r, PO_TIMEOUT, "no answer in %g s", c->timeout);
        else if (reset)
            set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "recv: %s", plat_sock_strerror(err));
        else
            set_res(r, PO_BROKEN, "closed without an answer");
    } else if (http && memcmp(b.data, "HTTP/", MIN(b.len, (size_t)5))) {
        set_res(r, PO_BROKEN, "not an HTTP response");
    } else if (http && !done && !(eof && h.hdr_done && h.clen < 0 && !h.chunked)) {
        if (reset)
            set_res(r, E_RESET(err) ? PO_RESET : PO_BROKEN, "response cut after %zu bytes: %s", total,
                    plat_sock_strerror(err));
        else
            set_res(r, PO_BROKEN, "response incomplete after %zu bytes", total);
    } else if (c->valid_contains && !contains(&b, c->valid_contains)) {
        set_res(r, PO_BROKEN, "the answer lacks \"%s\"", c->valid_contains);
    } else if (total < c->min_bytes) {
        set_res(r, PO_BROKEN, "%zu of %zu bytes", total, c->min_bytes);
    } else if (http) {
        set_res(r, PO_OK, "HTTP %d, %zu bytes", h.status, total);
    } else {
        set_res(r, PO_OK, "%zu bytes", total);
    }
    sb_free(&b);
}

static void run_stream(const probe_cfg *c, probe_ports *lp, probe_res *r, int http)
{
    sbuf req;
    sock_t s = tcp_connect(c, lp, r);
    if (s == SOCK_INVALID)
        return;
    sb_init(&req);
    if (http) {
        sb_printf(&req, "GET %s", c->path && *c->path ? c->path : "/");
        if (c->bad_word)
            sb_printf(&req, "%sq=%s", strchr(c->path ? c->path : "", '?') ? "&" : "?", c->bad_word);
        sb_printf(&req,
                  " HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
                  "Connection: close\r\n\r\n",
                  c->host ? c->host : c->ip);
    } else if (c->payload_len) {
        sb_append(&req, c->payload, c->payload_len);
    }
    if (!req.len || send_all(s, req.data, req.len, c->timeout, r) == 0)
        read_reply(c, s, http, r);
    sb_free(&req);
    plat_sock_close(s);
}

/* ---- tls ----------------------------------------------------------------- */

static void put16(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

size_t probe_client_hello(const char *sni, const char *alpn, int tls_version, uint8_t *buf, size_t cap)
{
    static const uint8_t c13[] = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};
    static const uint8_t c12[] = {0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8,
                                  0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35};
    static const uint8_t sigalgs[] = {0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
                                      0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01};
    static const uint8_t fixed[] = {
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,                                     /* ec_point_formats */
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, /* supported_groups */
        0x00, 0x23, 0x00, 0x00,                                                 /* session_ticket */
        0x00, 0x17, 0x00, 0x00,                                                 /* extended_master_secret */
        0xff, 0x01, 0x00, 0x01, 0x00,                                           /* renegotiation_info */
    };
    size_t sl = sni ? strlen(sni) : 0, al = alpn ? strlen(alpn) : 0, n = 0, ext;
    int v13 = tls_version != 12, v12 = tls_version != 13;
    if (sl > 253 || al > 64 || cap < 600 + sl + al)
        return 0;
    buf[n++] = 0x16;
    buf[n++] = 0x03;
    buf[n++] = 0x01;
    n += 2; /* record length */
    buf[n++] = 0x01;
    n += 3; /* handshake length */
    buf[n++] = 0x03;
    buf[n++] = 0x03;
    plat_random_bytes(buf + n, 32);
    n += 32;
    buf[n++] = 32;
    plat_random_bytes(buf + n, 32);
    n += 32;
    put16(buf + n, (v13 ? sizeof(c13) : 0) + (v12 ? sizeof(c12) : 0));
    n += 2;
    if (v13) {
        memcpy(buf + n, c13, sizeof(c13));
        n += sizeof(c13);
    }
    if (v12) {
        memcpy(buf + n, c12, sizeof(c12));
        n += sizeof(c12);
    }
    buf[n++] = 1;
    buf[n++] = 0;
    ext = n;
    n += 2;
    if (sl) {
        put16(buf + n, 0x0000);
        put16(buf + n + 2, sl + 5);
        put16(buf + n + 4, sl + 3);
        buf[n + 6] = 0;
        put16(buf + n + 7, sl);
        memcpy(buf + n + 9, sni, sl);
        n += 9 + sl;
    }
    memcpy(buf + n, fixed, sizeof(fixed));
    n += sizeof(fixed);
    memcpy(buf + n, sigalgs, sizeof(sigalgs));
    n += sizeof(sigalgs);
    if (al) {
        put16(buf + n, 0x0010);
        put16(buf + n + 2, al + 3);
        put16(buf + n + 4, al + 1);
        buf[n + 6] = (uint8_t)al;
        memcpy(buf + n + 7, alpn, al);
        n += 7 + al;
    }
    if (v13) {
        static const uint8_t both[] = {0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03};
        static const uint8_t only[] = {0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04};
        static const uint8_t psk[] = {0x00, 0x2d, 0x00, 0x02, 0x01, 0x01};
        static const uint8_t ks[] = {0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
        memcpy(buf + n, v12 ? both : only, v12 ? sizeof(both) : sizeof(only));
        n += v12 ? sizeof(both) : sizeof(only);
        memcpy(buf + n, psk, sizeof(psk));
        n += sizeof(psk);
        memcpy(buf + n, ks, sizeof(ks));
        n += sizeof(ks);
        plat_random_bytes(buf + n, 32); /* any 32 bytes make an x25519 public key */
        n += 32;
    }
    put16(buf + ext, n - ext - 2);
    put16(buf + 3, n - 5);
    buf[6] = 0;
    put16(buf + 7, n - 9);
    return n;
}

static void run_tls(const probe_cfg *c, probe_ports *lp, probe_res *r)
{
    uint8_t ch[1024], buf[16384], rec[5];
    uint8_t *hs = NULL; /* handshake messages, across records */
    size_t hsn = 0, hscap = 0, total = 0, recfill = 0, recleft = 0;
    int rtype = 0, got_sh = 0, done = 0, alert = 0, bad = 0, err = 0, k = 0;
    sbuf b;
    size_t n = probe_client_hello(c->host, c->alpn ? c->alpn : "http/1.1", c->tls_version, ch, sizeof(ch));
    sock_t s;

    if (!n) {
        set_res(r, PO_FAILED, "cannot build a ClientHello for this name");
        return;
    }
    s = tcp_connect(c, lp, r);
    if (s == SOCK_INVALID)
        return;
    if (send_all(s, ch, n, c->timeout, r) < 0) {
        plat_sock_close(s);
        return;
    }
    sb_init(&b);
    while (!(done && total >= c->min_bytes) && !alert && !bad) {
        k = recv_wait(s, buf, sizeof(buf), c->timeout, &err);
        if (k <= 0)
            break;
        keep(&b, buf, (size_t)k);
        total += (size_t)k;
        /* walk the records */
        for (int i = 0; i < k && !bad;) {
            if (recleft == 0) {
                rec[recfill++] = buf[i++];
                if (recfill < 5)
                    continue;
                recfill = 0;
                rtype = rec[0];
                recleft = (size_t)rec[3] << 8 | rec[4];
                if (rtype < 0x14 || rtype > 0x17 || rec[1] != 3) {
                    bad = 1;
                    break;
                }
                if (rtype == 0x15)
                    alert = 1;
                if (rtype == 0x17 && got_sh)
                    done = 1; /* TLS 1.3: the encrypted flight follows ServerHello */
                continue;
            }
            {
                size_t take = MIN(recleft, (size_t)(k - i));
                if (rtype == 0x16 && hsn + take <= 1u << 20) {
                    if (hsn + take > hscap) {
                        hscap = (hsn + take) * 2;
                        hs = xrealloc(hs, hscap);
                    }
                    memcpy(hs + hsn, buf + i, take);
                    hsn += take;
                }
                i += (int)take;
                recleft -= take;
            }
            /* whole handshake messages */
            while (hsn >= 4) {
                size_t ml = (size_t)hs[1] << 16 | (size_t)hs[2] << 8 | hs[3];
                if (hsn < 4 + ml)
                    break;
                if (hs[0] == 2)
                    got_sh = 1;
                if (hs[0] == 14 && got_sh)
                    done = 1; /* TLS 1.2: ServerHelloDone ends the server's flight */
                memmove(hs, hs + 4 + ml, hsn - 4 - ml);
                hsn -= 4 + ml;
            }
        }
    }
    r->bytes = total;
    if (c->injected_contains && contains(&b, c->injected_contains))
        set_res(r, PO_INJECTED, "the answer contains \"%s\"", c->injected_contains);
    else if (done && total >= c->min_bytes)
        set_res(r, PO_OK, "server flight complete, %zu bytes", total);
    else if (bad)
        set_res(r, PO_BROKEN, "not TLS (%zu bytes)", total);
    else if (alert)
        set_res(r, got_sh ? PO_BROKEN : PO_FAILED, "TLS alert%s", got_sh ? " after ServerHello" : "");
    else if (k == -1)
        set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "%s%s", got_sh ? "after ServerHello: " : "",
                plat_sock_strerror(err));
    else if (!total && k == -2)
        set_res(r, PO_TIMEOUT, "no ServerHello in %g s", c->timeout);
    else if (!total)
        set_res(r, PO_BROKEN, "closed without ServerHello");
    else
        set_res(r, PO_BROKEN, "%s, %zu bytes", got_sh ? "server flight incomplete" : "no ServerHello", total);
    free(hs);
    sb_free(&b);
    plat_sock_close(s);
}

/* ---- dns ----------------------------------------------------------------- */

size_t probe_dns_query(const char *name, int aaaa, uint16_t id, uint8_t *buf, size_t cap)
{
    size_t n = 12;
    const char *p = name;
    if (strlen(name) > 253 || cap < strlen(name) + 18)
        return 0;
    memset(buf, 0, 12);
    put16(buf, id);
    buf[2] = 0x01; /* RD */
    buf[5] = 1;    /* QDCOUNT */
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || l > 63)
            return 0;
        buf[n++] = (uint8_t)l;
        memcpy(buf + n, p, l);
        n += l;
        p += l;
        if (*p == '.')
            p++;
    }
    buf[n++] = 0;
    put16(buf + n, aaaa ? 28 : 1);
    put16(buf + n + 2, 1);
    return n + 4;
}

static int skip_name(const uint8_t *p, size_t n, size_t *off)
{
    for (int guard = 0; guard < 128; guard++) {
        uint8_t l;
        if (*off >= n)
            return -1;
        l = p[*off];
        if (l == 0) {
            (*off)++;
            return 0;
        }
        if ((l & 0xc0) == 0xc0) {
            *off += 2;
            return *off <= n ? 0 : -1;
        }
        if (l & 0xc0)
            return -1;
        *off += 1u + l;
    }
    return -1;
}

int probe_dns_parse(const uint8_t *p, size_t n, uint16_t id, char out[][46], int max, int *rcode)
{
    size_t off = 12;
    int qd, an, got = 0;
    if (n < 12 || ((size_t)p[0] << 8 | p[1]) != id || !(p[2] & 0x80))
        return -1;
    *rcode = p[3] & 0x0f;
    qd = p[4] << 8 | p[5];
    an = p[6] << 8 | p[7];
    for (int i = 0; i < qd; i++) {
        if (skip_name(p, n, &off) < 0)
            return -1;
        off += 4;
    }
    for (int i = 0; i < an; i++) {
        unsigned type, rdlen;
        if (skip_name(p, n, &off) < 0 || off + 10 > n)
            return -1;
        type = (unsigned)p[off] << 8 | p[off + 1];
        rdlen = (unsigned)p[off + 8] << 8 | p[off + 9];
        off += 10;
        if (off + rdlen > n)
            return -1;
        if (got < max && ((type == 1 && rdlen == 4) || (type == 28 && rdlen == 16))) {
            if (inet_ntop(type == 1 ? AF_INET : AF_INET6, p + off, out[got], 46))
                got++;
        }
        off += rdlen;
    }
    return got;
}

/* Is addr in the comma list (addresses or CIDR prefixes)? */
static int addr_in_list(const char *addr, const char *list)
{
    uint8_t a[16], m[16];
    int fam = strchr(addr, ':') ? AF_INET6 : AF_INET, alen = fam == AF_INET6 ? 16 : 4;
    if (!list || inet_pton(fam, addr, a) != 1)
        return 0;
    while (*list) {
        const char *end = strchr(list, ',');
        size_t l = end ? (size_t)(end - list) : strlen(list);
        char item[64];
        if (l && l < sizeof(item)) {
            char *slash;
            int bits = alen * 8;
            memcpy(item, list, l);
            item[l] = 0;
            if ((slash = strchr(item, '/')) != NULL) {
                *slash = 0;
                bits = atoi(slash + 1);
            }
            if (bits >= 0 && bits <= alen * 8 && inet_pton(fam, item, m) == 1) {
                int ok = 1;
                for (int i = 0; i < bits && ok; i++)
                    ok = ((a[i / 8] ^ m[i / 8]) & (0x80 >> (i % 8))) == 0;
                if (ok)
                    return 1;
            }
        }
        list += l;
        if (*list == ',')
            list++;
    }
    return 0;
}

static void dns_verdict(const probe_cfg *c, const uint8_t *msg, size_t n, uint16_t id, probe_res *r)
{
    char addrs[16][46];
    int rcode = 0, na = probe_dns_parse(msg, n, id, addrs, 16, &rcode);
    if (na < 0) {
        set_res(r, PO_BROKEN, "malformed DNS answer");
        return;
    }
    if (rcode || na == 0) {
        set_res(r, PO_INJECTED, rcode ? "DNS error %d" : "no addresses in the answer", rcode);
        return;
    }
    for (int i = 0; i < na; i++)
        if (addr_in_list(addrs[i], c->dns_bad)) {
            set_res(r, PO_INJECTED, "forged answer %s", addrs[i]);
            return;
        }
    if (c->dns_expect) {
        for (int i = 0; i < na; i++)
            if (addr_in_list(addrs[i], c->dns_expect)) {
                set_res(r, PO_OK, "%s", addrs[i]);
                return;
            }
        set_res(r, PO_INJECTED, "unexpected answer %s", addrs[0]);
        return;
    }
    set_res(r, PO_OK, "%s", addrs[0]);
}

static void run_dns(const probe_cfg *c, probe_ports *lp, probe_res *r)
{
    uint8_t q[300], buf[4096];
    uint16_t id;
    size_t qn;
    int err = 0;
    sock_t s;

    plat_random_bytes(&id, sizeof(id)); /* not the GA's generator: workers run in parallel */
    qn = probe_dns_query(c->host ? c->host : "", c->dns_aaaa, id, q + 2, sizeof(q) - 2);

    if (!qn) {
        set_res(r, PO_FAILED, "bad name to query");
        return;
    }
    if (c->dns_tcp) {
        size_t have = 0, want = 0;
        s = tcp_connect(c, lp, r);
        if (s == SOCK_INVALID)
            return;
        put16(q, qn);
        if (send_all(s, q, qn + 2, c->timeout, r) == 0) {
            for (;;) {
                int k = recv_wait(s, buf + have, sizeof(buf) - have, c->timeout, &err);
                if (k <= 0) {
                    r->bytes = have;
                    if (k == -2)
                        set_res(r, have ? PO_BROKEN : PO_TIMEOUT, "no DNS answer in %g s", c->timeout);
                    else if (k == 0)
                        set_res(r, PO_BROKEN, "closed after %zu bytes", have);
                    else
                        set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "recv: %s", plat_sock_strerror(err));
                    break;
                }
                have += (size_t)k;
                if (have >= 2)
                    want = (size_t)buf[0] << 8 | buf[1];
                if (have >= 2 && have >= want + 2) {
                    r->bytes = have;
                    dns_verdict(c, buf + 2, want, id, r);
                    break;
                }
                if (have == sizeof(buf)) {
                    set_res(r, PO_BROKEN, "DNS answer too long");
                    break;
                }
            }
        }
        plat_sock_close(s);
        return;
    }
    s = bind_next(c, lp, SOCK_DGRAM, &err);
    if (s == SOCK_INVALID) {
        set_res(r, PO_FAILED, "no local port: %s", plat_sock_strerror(err));
        return;
    }
    plat_sock_nonblock(s, 1);
    if (connect(s, (const struct sockaddr *)&c->addr, (socklen_t)c->addrlen) < 0 ||
        send(s, (const char *)q + 2, (int)qn, 0) < 0) {
        err = plat_sock_err();
        set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "send: %s", plat_sock_strerror(err));
        plat_sock_close(s);
        return;
    }
    {
        uint64_t end = plat_now_ms() + (uint64_t)ms_of(c->timeout);
        for (;;) {
            uint64_t now = plat_now_ms();
            int k;
            if (now >= end) {
                set_res(r, PO_TIMEOUT, "no DNS answer in %g s", c->timeout);
                break;
            }
            k = recv_wait(s, buf, sizeof(buf), (double)(end - now) / 1000.0, &err);
            if (k == -2)
                continue;
            if (k < 0) {
                set_res(r, E_RESET(err) ? PO_RESET : PO_FAILED, "recv: %s", plat_sock_strerror(err));
                break;
            }
            if (k < 12 || ((size_t)buf[0] << 8 | buf[1]) != id)
                continue; /* not ours */
            r->bytes = (size_t)k;
            /* the first answer decides, as for a resolver */
            dns_verdict(c, buf, (size_t)k, id, r);
            break;
        }
    }
    plat_sock_close(s);
}

/* ---- exec ---------------------------------------------------------------- */

void probe_expand_cmd(const probe_cfg *c, const probe_ports *lp, sbuf *out)
{
    char ip[64];
    addr_text(c, ip, sizeof(ip));
    for (const char *p = c->cmd; *p; p++) {
        if (*p == '{') {
            const char *e = strchr(p, '}');
            size_t l = e ? (size_t)(e - p - 1) : 0;
            if (e && l == 6 && !memcmp(p + 1, "lports", 6)) {
                sb_printf(out, "%u-%u", (unsigned)lp->lo, (unsigned)lp->hi);
                p = e;
                continue;
            }
            if (e && l == 5 && !memcmp(p + 1, "lport", 5)) {
                sb_printf(out, "%u", (unsigned)lp->lo);
                p = e;
                continue;
            }
            if (e && l == 4 && !memcmp(p + 1, "host", 4)) {
                sb_puts(out, c->host ? c->host : ip);
                p = e;
                continue;
            }
            if (e && l == 2 && !memcmp(p + 1, "ip", 2)) {
                sb_puts(out, ip);
                p = e;
                continue;
            }
            if (e && l == 4 && !memcmp(p + 1, "port", 4)) {
                sb_printf(out, "%u", (unsigned)c->port);
                p = e;
                continue;
            }
        }
        sb_putc(out, *p);
    }
}

/* Runs cmd, collecting its output. Returns the exit code, -1 if it could
 * not start, -2 on timeout (the command is killed). */
static int spawn(const char *cmd, double timeout, sbuf *output)
{
    uint64_t end = plat_now_ms() + (uint64_t)ms_of(timeout);
#ifdef _WIN32
    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE rd, wr, nul, job, inherit[2];
    STARTUPINFOEXA si;
    SIZE_T alen = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attrs = NULL;
    PROCESS_INFORMATION pi;
    BOOL created;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION li;
    char *line = xasprintf("cmd.exe /d /s /c \"%s\"", cmd);
    DWORD code = 0;
    int rc = -1;

    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        free(line);
        return -1;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    nul = CreateFileA("NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, NULL);
    memset(&si, 0, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput = nul;
    si.StartupInfo.hStdOutput = si.StartupInfo.hStdError = wr;
    /* only these two handles reach the command, not the sockets of other probes */
    inherit[0] = wr;
    inherit[1] = nul;
    InitializeProcThreadAttributeList(NULL, 1, 0, &alen);
    attrs = xmalloc(alen);
    if (InitializeProcThreadAttributeList(attrs, 1, 0, &alen) &&
        UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit,
                                  nul != INVALID_HANDLE_VALUE ? 2 * sizeof(HANDLE) : sizeof(HANDLE), NULL, NULL))
        si.lpAttributeList = attrs;
    job = CreateJobObjectA(NULL, NULL);
    memset(&li, 0, sizeof(li));
    li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (job)
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &li, sizeof(li));
    created = CreateProcessA(NULL, line, NULL, NULL, TRUE,
                             CREATE_NO_WINDOW | CREATE_SUSPENDED | (si.lpAttributeList ? EXTENDED_STARTUPINFO_PRESENT : 0),
                             NULL, NULL, &si.StartupInfo, &pi);
    if (si.lpAttributeList)
        DeleteProcThreadAttributeList(attrs);
    free(attrs);
    if (!created) {
        CloseHandle(rd);
        CloseHandle(wr);
        if (nul != INVALID_HANDLE_VALUE)
            CloseHandle(nul);
        if (job)
            CloseHandle(job);
        free(line);
        return -1;
    }
    if (job)
        AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(wr);
    if (nul != INVALID_HANDLE_VALUE)
        CloseHandle(nul);
    for (;;) {
        DWORD avail = 0, got = 0, w;
        char buf[4096];
        while (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail &&
               ReadFile(rd, buf, (DWORD)MIN(avail, sizeof(buf)), &got, NULL) && got)
            keep(output, buf, got);
        w = WaitForSingleObject(pi.hProcess, 50);
        if (w == WAIT_OBJECT_0) {
            while (PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) && avail &&
                   ReadFile(rd, buf, (DWORD)MIN(avail, sizeof(buf)), &got, NULL) && got)
                keep(output, buf, got);
            GetExitCodeProcess(pi.hProcess, &code);
            rc = (int)code;
            break;
        }
        if (plat_now_ms() >= end) {
            if (job)
                TerminateJobObject(job, 1);
            else
                TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 2000);
            rc = -2;
            break;
        }
    }
    CloseHandle(pi.hProcess);
    CloseHandle(rd);
    if (job)
        CloseHandle(job);
    free(line);
    return rc;
#else
    int pfd[2], status = 0, rc = -1, open_pipe = 1;
    pid_t pid;
    if (pipe(pfd) < 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }
    if (pid == 0) {
        int nul = open("/dev/null", O_RDONLY);
        setpgid(0, 0);
        if (nul >= 0)
            dup2(nul, 0);
        dup2(pfd[1], 1);
        dup2(pfd[1], 2);
        /* nothing else of ours: the queue, the probes' sockets */
        for (int fd = 3; fd < 1024; fd++)
            close(fd);
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(pfd[1]);
    fcntl(pfd[0], F_SETFL, fcntl(pfd[0], F_GETFL) | O_NONBLOCK);
    for (;;) {
        uint64_t now = plat_now_ms();
        pid_t w;
        if (open_pipe) {
            struct pollfd p = {pfd[0], POLLIN, 0};
            int left = now < end ? (int)MIN(end - now, (uint64_t)100) : 0;
            if (poll(&p, 1, left) > 0) {
                char buf[4096];
                ssize_t k = read(pfd[0], buf, sizeof(buf));
                if (k > 0)
                    keep(output, buf, (size_t)k);
                else if (k == 0 || (errno != EAGAIN && errno != EINTR))
                    open_pipe = 0;
            }
        } else {
            plat_sleep_ms(20);
        }
        w = waitpid(pid, &status, WNOHANG);
        if (w == pid && !open_pipe) {
            rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            break;
        }
        if (w == pid) {
            /* exited: read what is left (children it left behind may keep the
             * pipe open, so do not wait for its end) */
            char buf[4096];
            ssize_t k;
            while ((k = read(pfd[0], buf, sizeof(buf))) > 0)
                keep(output, buf, (size_t)k);
            rc = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
            break;
        }
        if (plat_now_ms() >= end) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            rc = -2;
            break;
        }
    }
    close(pfd[0]);
    return rc;
#endif
}

static void run_exec(const probe_cfg *c, probe_ports *lp, probe_res *r)
{
    sbuf cmd, out;
    int rc;
    double limit = c->timeout > 0 ? c->timeout : 20;
    sb_init(&cmd);
    sb_init(&out);
    probe_expand_cmd(c, lp, &cmd);
    LOGD("probe", "exec: %s", cmd.data);
    rc = spawn(cmd.data, limit, &out);
    r->bytes = out.len;
    if (rc == -1)
        set_res(r, PO_FAILED, "cannot run the command");
    else if (rc == -2)
        set_res(r, PO_FAILED, "the command ran over %g s", limit);
    else if (c->injected_contains && contains(&out, c->injected_contains))
        set_res(r, PO_INJECTED, "the output contains \"%s\"", c->injected_contains);
    else if (rc != 0)
        set_res(r, contains(&out, "reset") || contains(&out, "Reset") ? PO_RESET : PO_FAILED, "exit code %d", rc);
    else if (c->valid_contains && !contains(&out, c->valid_contains))
        set_res(r, PO_BROKEN, "the output lacks \"%s\"", c->valid_contains);
    else
        set_res(r, PO_OK, "exit code 0");
    sb_free(&cmd);
    sb_free(&out);
}

/* ---- entry --------------------------------------------------------------- */

void probe_run(const probe_cfg *c, probe_ports *lp, probe_res *r)
{
    memset(r, 0, sizeof(*r));
    switch (c->kind) {
    case PROBE_HTTP:
        run_stream(c, lp, r, 1);
        break;
    case PROBE_TCP:
        run_stream(c, lp, r, 0);
        break;
    case PROBE_TLS:
        run_tls(c, lp, r);
        break;
    case PROBE_DNS:
        run_dns(c, lp, r);
        break;
    case PROBE_EXEC:
        run_exec(c, lp, r);
        break;
    case PROBE_EXTERNAL:
        set_res(r, PO_FAILED, "the external probe is run by the evaluator");
        break;
    }
}

int probe_parse_payload(const char *s, uint8_t **out, size_t *len)
{
    size_t n = 0;
    uint8_t *b = xmalloc(strlen(s) + 1);
    if (str_starts(s, "hex:")) {
        long k = hex_decode(s + 4, b, strlen(s));
        if (k < 0) {
            free(b);
            return -1;
        }
        *out = b;
        *len = (size_t)k;
        return 0;
    }
    for (const char *p = s; *p; p++) {
        if (*p != '\\') {
            b[n++] = (uint8_t)*p;
            continue;
        }
        p++;
        switch (*p) {
        case 'r': b[n++] = '\r'; break;
        case 'n': b[n++] = '\n'; break;
        case 't': b[n++] = '\t'; break;
        case '0': b[n++] = 0; break;
        case '\\': b[n++] = '\\'; break;
        case 'x': {
            char h[3] = {0, 0, 0};
            uint8_t v;
            if (!p[1] || !p[2]) {
                free(b);
                return -1;
            }
            h[0] = p[1];
            h[1] = p[2];
            if (hex_decode(h, &v, 1) != 1) {
                free(b);
                return -1;
            }
            b[n++] = v;
            p += 2;
            break;
        }
        default:
            free(b);
            return -1;
        }
    }
    *out = b;
    *len = n;
    return 0;
}
