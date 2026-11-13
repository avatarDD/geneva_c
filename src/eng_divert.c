/*
 * BSD packet backend: divert(4) sockets (docs/EXT.md, X13b).
 *
 *   FreeBSD  ipfw "divert PORT" rules (src/fw_bsd.c) send the packets to a
 *            socket bound to PORT: PF_DIVERT since FreeBSD 14, else
 *            AF_INET/IPPROTO_DIVERT; one socket takes IPv4 and IPv6
 *   OpenBSD  pf "divert-packet port PORT": one socket per family
 *
 * The divert port is fw.queue. recvfrom() gives each packet an address: zero
 * for an outbound packet, the receiving interface's address for an inbound
 * one (FreeBSD also puts the interface's name after it). Writing the bytes
 * back with that address sends the packet on its way (the kernel goes on
 * after the rule that diverted it), the same address carries the engine's
 * extra packets in the same direction. A diverted packet is a copy: nothing
 * is held in the kernel, so a dropped packet is one that is not written.
 *
 * As with WinDivert there are no conntrack rules: --first is counted by the
 * engine, and a strategy cannot mark packets or pick interfaces.
 */
#include "engine_int.h"

#if defined(__FreeBSD__) || defined(__OpenBSD__)

#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "geneva.h"
#include "log.h"

#ifndef IPPROTO_DIVERT
#  define IPPROTO_DIVERT 258
#endif
#if defined(__FreeBSD__) && !defined(PF_DIVERT)
#  define PF_DIVERT 44 /* FreeBSD 14's sys/socket.h */
#endif

#define DV_MAX_PACKET 65535

typedef union {
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
} dv_addr;

/* the packet's address and its socket, followed by its original bytes when
 * the verdict keeps them (data == NULL): the core holds no copy of those */
typedef struct {
    dv_addr addr;
    socklen_t alen;
    int fd;
    const uint8_t *data;
    size_t len;
} dv_pctx;

typedef struct {
    int fd[2]; /* IPv4 (FreeBSD: both), IPv6 (OpenBSD) */
    int nfd;
    int fw_on;
    uint8_t *buf;
} dv_state;

static int dv_socket(int family)
{
    int fd = -1;
#ifdef __FreeBSD__
    /* FreeBSD 14 and later; the same binary runs on 13 */
    fd = socket(PF_DIVERT, SOCK_RAW, 0);
    if (fd < 0 && (errno == EPROTONOSUPPORT || errno == EAFNOSUPPORT || errno == EPFNOSUPPORT))
#endif
        fd = socket(family, SOCK_RAW, IPPROTO_DIVERT);
    return fd;
}

static int dv_bind(int fd, int family, uint16_t port)
{
    dv_addr a;
    memset(&a, 0, sizeof(a));
    if (family == AF_INET6) {
        a.in6.sin6_family = AF_INET6;
        a.in6.sin6_port = htons(port);
        return bind(fd, &a.sa, sizeof(a.in6));
    }
    a.in.sin_family = AF_INET;
    a.in.sin_port = htons(port);
    return bind(fd, &a.sa, sizeof(a.in));
}

/* an inbound packet has the address of the interface it came in on */
static int dv_inbound(const dv_addr *a)
{
    static const uint8_t zero[16];
    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->in6.sin6_addr, zero, 16) != 0;
    return a->in.sin_addr.s_addr != 0;
}

static int dv_send(const dv_pctx *p, const uint8_t *data, size_t len)
{
    ssize_t n;
    do
        n = sendto(p->fd, data, len, 0, &p->addr.sa, p->alen);
    while (n < 0 && errno == EINTR);
    if (n < 0) {
        LOGD("engine", "divert sendto (%zu bytes): %s", len, strerror(errno));
        return -1;
    }
    if ((size_t)n != len) {
        LOGD("engine", "divert sendto: %zd of %zu bytes", n, len);
        return -1;
    }
    return 0;
}

static int dv_be_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    const dv_pctx *p = pctx;
    (void)w;
    if (!accept)
        return 0; /* not writing it back is dropping */
    if (!data) {
        if (!p->data) {
            LOGW("engine", "lost the bytes of a delayed packet");
            return -1;
        }
        return dv_send(p, p->data, p->len);
    }
    return dv_send(p, data, len);
}

static int dv_be_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    (void)w;
    return dv_send(pctx, data, len);
}

static void dv_be_meta(const void *pctx, uint32_t *mark, uint32_t *ifin, uint32_t *ifout)
{
    const dv_pctx *p = pctx;
    *mark = 0, *ifin = 0, *ifout = 0;
#ifdef __FreeBSD__
    /* FreeBSD puts the receiving interface's name after sin_addr, cut to 7
     * characters (strlcpy into the 8 bytes of sin_zero) */
    if (p->addr.sa.sa_family == AF_INET && dv_inbound(&p->addr) && p->addr.in.sin_zero[0]) {
        char name[sizeof(p->addr.in.sin_zero) + 1];
        memcpy(name, p->addr.in.sin_zero, sizeof(p->addr.in.sin_zero));
        name[sizeof(p->addr.in.sin_zero)] = 0;
        *ifin = if_nametoindex(name);
    }
#else
    (void)p;
#endif
}

static int dv_be_open(engine *e, sbuf *err)
{
    engine_opts *o = e->o;
    dv_state *s = xcalloc(1, sizeof(*s));
    static const int fams[2] = {AF_INET, AF_INET6};
    e->bs = s;
    s->fd[0] = s->fd[1] = -1;
    s->buf = xmalloc(DV_MAX_PACKET);
#ifdef __FreeBSD__
    s->nfd = 1;
#else
    s->nfd = 2;
#endif
    for (int i = 0; i < s->nfd; i++) {
        int en;
        s->fd[i] = dv_socket(fams[i]);
        if (s->fd[i] < 0) {
            en = errno;
            sb_printf(err, "divert socket: %s", strerror(en));
#ifdef __FreeBSD__
            if (en == EPROTONOSUPPORT || en == EAFNOSUPPORT || en == EPFNOSUPPORT)
                sb_puts(err, " (load the module: kldload ipdivert)");
#endif
            e->err_where = "divert";
            return EXIT_PRIV;
        }
        if (dv_bind(s->fd[i], fams[i], o->fw.queue) < 0) {
            en = errno;
            sb_printf(err, "binding the divert socket to port %u: %s", o->fw.queue, strerror(en));
            e->err_where = "divert";
            return en == EADDRINUSE ? EXIT_FAIL : EXIT_PRIV;
        }
        {
            int rb = 4 << 20;
            if (setsockopt(s->fd[i], SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb)) < 0)
                LOGD("engine", "SO_RCVBUF: %s", strerror(errno));
        }
    }
    if (o->apply_fw) {
        if (fw_up(&o->fw, err) < 0) {
            e->err_where = "firewall";
            return EXIT_FIREWALL;
        }
        s->fw_on = 1;
        e->fw_name = fw_backend_name(o->fw.backend);
        LOGI("engine", "firewall rules applied (%s)", e->fw_name);
    }
    LOGI("engine", "listening on divert port %u", o->fw.queue);
    return EXIT_OK;
}

/* reads what waits on socket i: up to 64 packets, then back to the timers */
static int dv_read(engine *e, int i)
{
    dv_state *s = e->bs;
    eng_worker *w = &e->w[0];
    for (int k = 0; k < 64; k++) {
        dv_pctx p;
        ssize_t n;
        uint64_t before;
        memset(&p, 0, sizeof(p));
        p.alen = sizeof(p.addr);
        n = recvfrom(s->fd[i], s->buf, DV_MAX_PACKET, MSG_DONTWAIT, &p.addr.sa, &p.alen);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (errno == ENOBUFS) {
                w->c.overruns++;
                continue;
            }
            LOGE("engine", "divert recvfrom: %s", strerror(errno));
            return -1;
        }
        if (n == 0)
            return 0;
        p.fd = s->fd[i];
        p.data = s->buf;
        p.len = (size_t)n;
        before = w->dl_order;
        engine_packet(w, s->buf, (size_t)n, dv_inbound(&p.addr) ? DIR_IN : DIR_OUT, &p);
        if (w->dl_order != before) {
            /* delayed packets keep a copy of pctx: its pointer to the
             * buffer must not outlive the packet (they carry their own
             * bytes) */
            for (size_t j = 0; j < w->ndl; j++) {
                dv_pctx *q = (dv_pctx *)w->dl[j].pctx;
                if (q->data == s->buf)
                    q->data = NULL;
            }
        }
    }
    return 0;
}

static void dv_be_stop(engine *e)
{
    dv_state *s = e->bs;
    if (!s)
        return;
    if (s->fw_on) {
        fw_down(&e->o->fw);
        s->fw_on = 0;
    }
    /* what was diverted before the rules came down goes on unchanged */
    plat_mutex_lock(&e->lock);
    for (int i = 0; i < s->nfd; i++) {
        for (;;) {
            dv_pctx p;
            ssize_t n;
            memset(&p, 0, sizeof(p));
            p.alen = sizeof(p.addr);
            n = recvfrom(s->fd[i], s->buf, DV_MAX_PACKET, MSG_DONTWAIT, &p.addr.sa, &p.alen);
            if (n <= 0)
                break;
            p.fd = s->fd[i];
            dv_send(&p, s->buf, (size_t)n);
        }
    }
    plat_mutex_unlock(&e->lock);
}

static void dv_be_close(engine *e)
{
    dv_state *s = e->bs;
    if (!s)
        return;
    for (int i = 0; i < 2; i++)
        if (s->fd[i] >= 0)
            close(s->fd[i]);
    free(s->buf);
    free(s);
    e->bs = NULL;
}

static size_t dv_be_pollfds(engine *e, plat_pollfd *fds, size_t max)
{
    dv_state *s = e->bs;
    size_t n = 0;
    for (int i = 0; i < s->nfd && n < max; i++) {
        fds[n].fd = s->fd[i];
        fds[n].events = POLLIN;
        fds[n].revents = 0;
        n++;
    }
    return n;
}

static int dv_be_ready(engine *e, const plat_pollfd *fds, size_t n)
{
    dv_state *s = e->bs;
    for (size_t i = 0; i < n && i < (size_t)s->nfd; i++)
        if ((fds[i].revents & POLLIN) && dv_read(e, (int)i) < 0)
            return -1;
    return 0;
}

const backend divert_backend = {
    "divert",
    sizeof(dv_pctx),
    dv_be_open,
    dv_be_stop,
    dv_be_close,
    dv_be_pollfds,
    dv_be_ready,
    dv_be_verdict,
    dv_be_inject,
    1,    /* --first: no conntrack in the rules, the engine counts */
    NULL, /* no capture filter: rules */
    NULL,
    dv_be_meta,
    NULL, /* inject_x: no marks or interfaces, x-action packets go through inject */
    NULL, /* detach: a diverted packet is a copy, the stack is not held up */
    NULL, /* worker_fd: one socket (--ext-workers is Linux only) */
    NULL,
    NULL, /* healthy: no conntrack mark (Linux only) */
};

#endif
