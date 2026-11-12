#include "ctnl.h"

#include <string.h>

/* ---- messages (every platform: the tests) ---------------------------------- */

#define A4(n) (((n) + 3u) & ~3u)
#define NLH 16
#define NFGEN 4
#define NLA_F_NESTED 0x8000
#define NLA_TYPE_MASK 0x3fff
#define NLMSG_ERROR_ 2
#define NLM_F_REQUEST_ 1
#define T_GET ((1 << 8) | 1) /* NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET */
#define T_NEW ((1 << 8) | 0) /* IPCTNL_MSG_CT_NEW */

enum { CTA_TUPLE_ORIG = 1, CTA_PROTOINFO = 4, CTA_COUNTERS_ORIG = 9, CTA_COUNTERS_REPLY = 10 };
enum { CTA_TUPLE_IP = 1, CTA_TUPLE_PROTO = 2 };
enum { CTA_IP_V4_SRC = 1, CTA_IP_V4_DST = 2, CTA_IP_V6_SRC = 3, CTA_IP_V6_DST = 4 };
enum { CTA_PROTO_NUM = 1, CTA_PROTO_SRC_PORT = 2, CTA_PROTO_DST_PORT = 3 };
enum { CTA_COUNTERS_PACKETS = 1, CTA_COUNTERS_BYTES = 2, CTA_COUNTERS32_PACKETS = 3, CTA_COUNTERS32_BYTES = 4 };
enum { CTA_PROTOINFO_TCP = 1, CTA_PROTOINFO_TCP_STATE = 1 };

/* netlink's own fields in host order, the attributes' values big endian */
static void h16put(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void h32put(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint16_t h16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}
static uint32_t h32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}
static uint64_t be(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++)
        v = v << 8 | p[i];
    return v;
}

typedef struct {
    uint8_t *b;
    size_t cap, n;
    int bad;
} wbuf;

static size_t attr_open(wbuf *w, uint16_t type)
{
    size_t at = w->n;
    if (w->n + 4 > w->cap) {
        w->bad = 1;
        return at;
    }
    h16put(w->b + w->n + 2, (uint16_t)(type | NLA_F_NESTED));
    w->n += 4;
    return at;
}

static void attr_close(wbuf *w, size_t at)
{
    if (!w->bad)
        h16put(w->b + at, (uint16_t)(w->n - at));
}

static void attr(wbuf *w, uint16_t type, const void *d, size_t len)
{
    if (w->n + A4(4 + len) > w->cap) {
        w->bad = 1;
        return;
    }
    h16put(w->b + w->n, (uint16_t)(4 + len));
    h16put(w->b + w->n + 2, type);
    memcpy(w->b + w->n + 4, d, len);
    memset(w->b + w->n + 4 + len, 0, A4(4 + len) - (4 + len));
    w->n += A4(4 + len);
}

size_t ctnl_build_get(uint8_t *buf, size_t cap, const ctnl_tuple *t, uint32_t seq)
{
    wbuf w = {buf, cap, 0, 0};
    size_t tup, ip, pr;
    uint8_t port[2];
    int v6 = t->ver == 6;
    if (cap < NLH + NFGEN)
        return 0;
    memset(buf, 0, NLH + NFGEN);
    h16put(buf + 4, T_GET);
    h16put(buf + 6, NLM_F_REQUEST_);
    h32put(buf + 8, seq);
    buf[NLH] = v6 ? 10 : 2; /* AF_INET6, AF_INET */
    w.n = NLH + NFGEN;
    tup = attr_open(&w, CTA_TUPLE_ORIG);
    ip = attr_open(&w, CTA_TUPLE_IP);
    attr(&w, v6 ? CTA_IP_V6_SRC : CTA_IP_V4_SRC, t->src, v6 ? 16 : 4);
    attr(&w, v6 ? CTA_IP_V6_DST : CTA_IP_V4_DST, t->dst, v6 ? 16 : 4);
    attr_close(&w, ip);
    pr = attr_open(&w, CTA_TUPLE_PROTO);
    attr(&w, CTA_PROTO_NUM, &t->proto, 1);
    port[0] = (uint8_t)(t->sport >> 8), port[1] = (uint8_t)t->sport;
    attr(&w, CTA_PROTO_SRC_PORT, port, 2);
    port[0] = (uint8_t)(t->dport >> 8), port[1] = (uint8_t)t->dport;
    attr(&w, CTA_PROTO_DST_PORT, port, 2);
    attr_close(&w, pr);
    attr_close(&w, tup);
    if (w.bad)
        return 0;
    h32put(buf, (uint32_t)w.n);
    return w.n;
}

/* Calls fn for each attribute of [p, p+n) */
typedef void (*attr_fn)(uint16_t type, const uint8_t *d, size_t n, void *ud);
static void attrs(const uint8_t *p, size_t n, attr_fn fn, void *ud)
{
    while (n >= 4) {
        uint16_t len = h16(p);
        if (len < 4 || len > n)
            return;
        fn((uint16_t)(h16(p + 2) & NLA_TYPE_MASK), p + 4, len - 4u, ud);
        if (A4(len) >= n)
            return;
        p += A4(len);
        n -= A4(len);
    }
}

static void on_ip(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    ctnl_tuple *t = ud;
    if ((type == CTA_IP_V4_SRC || type == CTA_IP_V4_DST) && n == 4) {
        t->ver = 4;
        memcpy(type == CTA_IP_V4_SRC ? t->src : t->dst, d, 4);
    } else if ((type == CTA_IP_V6_SRC || type == CTA_IP_V6_DST) && n == 16) {
        t->ver = 6;
        memcpy(type == CTA_IP_V6_SRC ? t->src : t->dst, d, 16);
    }
}

static void on_proto(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    ctnl_tuple *t = ud;
    if (type == CTA_PROTO_NUM && n >= 1)
        t->proto = d[0];
    else if (type == CTA_PROTO_SRC_PORT && n >= 2)
        t->sport = (uint16_t)be(d, 2);
    else if (type == CTA_PROTO_DST_PORT && n >= 2)
        t->dport = (uint16_t)be(d, 2);
}

static void on_tuple(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    if (type == CTA_TUPLE_IP)
        attrs(d, n, on_ip, ud);
    else if (type == CTA_TUPLE_PROTO)
        attrs(d, n, on_proto, ud);
}

typedef struct {
    uint64_t *pk, *by;
} ctr_ud;

static void on_counters(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    ctr_ud *c = ud;
    if ((type == CTA_COUNTERS_PACKETS && n == 8) || (type == CTA_COUNTERS32_PACKETS && n == 4))
        *c->pk = be(d, n);
    else if ((type == CTA_COUNTERS_BYTES && n == 8) || (type == CTA_COUNTERS32_BYTES && n == 4))
        *c->by = be(d, n);
}

static void on_tcpinfo(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    if (type == CTA_PROTOINFO_TCP_STATE && n >= 1)
        ((ctnl_entry *)ud)->tcp_state = d[0];
}

static void on_protoinfo(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    if (type == CTA_PROTOINFO_TCP)
        attrs(d, n, on_tcpinfo, ud);
}

static void on_top(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    ctnl_entry *e = ud;
    ctr_ud c;
    switch (type) {
    case CTA_TUPLE_ORIG:
        attrs(d, n, on_tuple, &e->t);
        break;
    case CTA_PROTOINFO:
        attrs(d, n, on_protoinfo, e);
        break;
    case CTA_COUNTERS_ORIG:
        c.pk = &e->opackets, c.by = &e->obytes;
        attrs(d, n, on_counters, &c);
        break;
    case CTA_COUNTERS_REPLY:
        c.pk = &e->rpackets, c.by = &e->rbytes;
        attrs(d, n, on_counters, &c);
        break;
    }
}

int ctnl_parse(const uint8_t *b, size_t n, const ctnl_tuple *(*lookup)(uint32_t seq, void *ctx), ctnl_cb cb,
               void *ctx)
{
    int k = 0;
    while (n >= NLH) {
        uint32_t len = h32(b);
        uint16_t type = h16(b + 4);
        ctnl_entry e;
        if (len < NLH || len > n)
            break;
        memset(&e, 0, sizeof(e));
        if (type == T_NEW && len >= NLH + NFGEN) {
            attrs(b + NLH + NFGEN, len - NLH - NFGEN, on_top, &e);
            if (e.t.ver) {
                e.found = 1;
                cb(&e, ctx);
                k++;
            }
        } else if (type == NLMSG_ERROR_ && len >= NLH + 4) {
            int32_t err;
            const ctnl_tuple *t;
            memcpy(&err, b + NLH, 4);
            if (err != 0 && lookup && (t = lookup(h32(b + 8), ctx)) != NULL) {
                e.t = *t;
                cb(&e, ctx);
                k++;
            }
        }
        if (A4(len) >= n)
            break;
        b += A4(len);
        n -= A4(len);
    }
    return k;
}

#ifdef __linux__

#  include <errno.h>
#  include <stdlib.h>
#  include <sys/socket.h>
#  include <unistd.h>

#  ifndef AF_NETLINK
#    define AF_NETLINK 16
#  endif
#  define NETLINK_NETFILTER 12
#  define RING 1024
#  define RX (65536 + 4096)

struct sockaddr_nl_ {
    sa_family_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct ctnl {
    int fd;
    uint32_t seq;
    ctnl_tuple ring[RING]; /* the tuple of request seq, at seq % RING */
    uint8_t rx[RX];
    ctnl_cb cb;
    void *ctx;
};

int ctnl_fd(const ctnl *c) { return c->fd; }

ctnl *ctnl_open(sbuf *err)
{
    ctnl *c = xcalloc(1, sizeof(*c));
    struct sockaddr_nl_ sa;
    int rb = 1 << 20;
    c->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
    if (c->fd < 0) {
        sb_printf(err, "ctnetlink socket: %s", strerror(errno));
        free(c);
        return NULL;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(c->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        sb_printf(err, "ctnetlink bind: %s", strerror(errno));
        ctnl_close(c);
        return NULL;
    }
    if (setsockopt(c->fd, SOL_SOCKET, 33 /* SO_RCVBUFFORCE */, &rb, sizeof(rb)) < 0)
        setsockopt(c->fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
    return c;
}

void ctnl_close(ctnl *c)
{
    if (!c)
        return;
    if (c->fd >= 0)
        close(c->fd);
    free(c);
}

int ctnl_request(ctnl *c, const ctnl_tuple *t)
{
    uint8_t b[160];
    struct sockaddr_nl_ sa;
    size_t n;
    uint32_t seq = ++c->seq;
    n = ctnl_build_get(b, sizeof(b), t, seq);
    if (!n)
        return 0;
    c->ring[seq % RING] = *t;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    return sendto(c->fd, b, n, MSG_DONTWAIT, (struct sockaddr *)&sa, sizeof(sa)) == (ssize_t)n ? 0 : -1;
}

static const ctnl_tuple *lookup(uint32_t seq, void *ctx)
{
    ctnl *c = ctx;
    /* only a request of the last RING */
    return c->seq - seq < RING ? &c->ring[seq % RING] : NULL;
}

static void relay(const ctnl_entry *e, void *ctx)
{
    ctnl *c = ctx;
    c->cb(e, c->ctx);
}

int ctnl_read(ctnl *c, ctnl_cb cb, void *ctx)
{
    ssize_t r = recv(c->fd, c->rx, sizeof(c->rx), MSG_DONTWAIT);
    if (r < 0)
        return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS ? 0 : -1;
    c->cb = cb;
    c->ctx = ctx;
    return ctnl_parse(c->rx, (size_t)r, lookup, relay, c);
}

#else /* not Linux */

ctnl *ctnl_open(sbuf *err)
{
    sb_puts(err, "ctnetlink is Linux only");
    return NULL;
}
void ctnl_close(ctnl *c) { (void)c; }
int ctnl_fd(const ctnl *c)
{
    (void)c;
    return -1;
}
int ctnl_request(ctnl *c, const ctnl_tuple *t)
{
    (void)c, (void)t;
    return -1;
}
int ctnl_read(ctnl *c, ctnl_cb cb, void *ctx)
{
    (void)c, (void)cb, (void)ctx;
    return -1;
}
#endif
