#include "nfq.h"

#ifdef __linux__

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "log.h"

/* Netlink and nfnetlink_queue ABI, defined here so the build needs no kernel
 * headers (router SDKs ship old or partial ones). Values are part of the
 * stable kernel ABI. */
#ifndef AF_NETLINK
#  define AF_NETLINK 16
#endif
#define NETLINK_NETFILTER 12

#define NLMSG_NOOP 1
#define NLMSG_ERROR 2
#define NLMSG_DONE 3
#define NLMSG_OVERRUN 4
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4

#define NFNL_SUBSYS_QUEUE 3
#define NFQNL_MSG_PACKET 0
#define NFQNL_MSG_VERDICT 1
#define NFQNL_MSG_CONFIG 2

#define NFQNL_CFG_CMD_BIND 1
#define NFQNL_CFG_CMD_UNBIND 2
#define NFQNL_CFG_CMD_PF_BIND 3
#define NFQNL_CFG_CMD_PF_UNBIND 4

#define NFQA_CFG_CMD 1
#define NFQA_CFG_PARAMS 2
#define NFQA_CFG_QUEUE_MAXLEN 3
#define NFQA_CFG_MASK 4
#define NFQA_CFG_FLAGS 5
#define NFQA_CFG_F_FAIL_OPEN 1
#define NFQNL_COPY_PACKET 2

#define NFQA_PACKET_HDR 1
#define NFQA_VERDICT_HDR 2
#define NFQA_MARK 3
#define NFQA_IFINDEX_INDEV 5
#define NFQA_IFINDEX_OUTDEV 6
#define NFQA_PAYLOAD 10

#define NLA_TYPE_MASK 0x3fff

#ifndef SOL_NETLINK
#  define SOL_NETLINK 270
#endif
#ifndef SO_RCVBUFFORCE
#  define SO_RCVBUFFORCE 33
#endif

#define ALIGN4(n) (((n) + 3u) & ~3u)
#define NLH_LEN 16
#define NFGEN_LEN 4
#define RXBUF (65536 + 4096)
#define TXBUF (65536 + 256)

struct sockaddr_nl_ {
    sa_family_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct nfq {
    int fd;
    uint16_t queue;
    uint32_t seq;
    uint8_t *rx, *tx;
};

int nfq_fd(const nfq *q) { return q->fd; }

/* ---- message building ---------------------------------------------------- */

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint16_t get16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t get32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* Starts a message in q->tx: nlmsghdr + nfgenmsg. Returns the length so far. */
static size_t msg_begin(nfq *q, uint8_t type, uint16_t flags, uint16_t res_id)
{
    uint8_t *b = q->tx;
    memset(b, 0, NLH_LEN + NFGEN_LEN);
    put16(b + 4, (uint16_t)((NFNL_SUBSYS_QUEUE << 8) | type));
    put16(b + 6, (uint16_t)(NLM_F_REQUEST | flags));
    put32(b + 8, ++q->seq);
    b[NLH_LEN] = 0; /* AF_UNSPEC */
    b[NLH_LEN + 1] = 0; /* NFNETLINK_V0 */
    put16(b + NLH_LEN + 2, htons(res_id));
    return NLH_LEN + NFGEN_LEN;
}

static size_t put_attr(nfq *q, size_t off, uint16_t type, const void *data, size_t len)
{
    uint8_t *b = q->tx + off;
    put16(b, (uint16_t)(4 + len));
    put16(b + 2, type);
    if (len)
        memcpy(b + 4, data, len);
    memset(b + 4 + len, 0, ALIGN4(4 + len) - (4 + len));
    return off + ALIGN4(4 + len);
}

static int msg_send(nfq *q, size_t len)
{
    struct sockaddr_nl_ sa;
    ssize_t r;
    put32(q->tx, (uint32_t)len);
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    do
        r = sendto(q->fd, q->tx, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    while (r < 0 && errno == EINTR);
    return r == (ssize_t)len ? 0 : -1;
}

/* ---- receiving ----------------------------------------------------------- */

static void parse_packet(const uint8_t *p, size_t len, nfq_msg *m)
{
    memset(m, 0, sizeof(*m));
    while (len >= 4) {
        uint16_t alen = get16(p), type = get16(p + 2) & NLA_TYPE_MASK;
        const uint8_t *d = p + 4;
        size_t dlen;
        if (alen < 4 || alen > len)
            break;
        dlen = alen - 4u;
        switch (type) {
        case NFQA_PACKET_HDR:
            if (dlen >= 7) {
                m->id = ntohl(get32(d));
                m->hw_proto = ntohs(get16(d + 4));
                m->hook = d[6];
            }
            break;
        case NFQA_MARK:
            if (dlen >= 4)
                m->mark = ntohl(get32(d));
            break;
        case NFQA_IFINDEX_INDEV:
            if (dlen >= 4)
                m->indev = ntohl(get32(d));
            break;
        case NFQA_IFINDEX_OUTDEV:
            if (dlen >= 4)
                m->outdev = ntohl(get32(d));
            break;
        case NFQA_PAYLOAD:
            m->data = d;
            m->len = dlen;
            break;
        }
        if (ALIGN4(alen) >= len)
            break;
        p += ALIGN4(alen);
        len -= ALIGN4(alen);
    }
}

/* Walks the messages of one datagram. Packets go to cb; an error message
 * matching want_seq is stored in *ack (0 = success, else errno). */
static int dispatch(nfq *q, size_t n, nfq_cb cb, void *ctx, uint32_t want_seq, int *ack)
{
    const uint8_t *b = q->rx;
    int npk = 0;
    while (n >= NLH_LEN) {
        uint32_t len = get32(b), seq = get32(b + 8);
        uint16_t type = get16(b + 4);
        if (len < NLH_LEN || len > n)
            break;
        if (type == NLMSG_ERROR) {
            if (len >= NLH_LEN + 4 && ack && seq == want_seq) {
                int32_t e;
                memcpy(&e, b + NLH_LEN, 4);
                *ack = -e;
            }
        } else if (type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) &&
                   len >= NLH_LEN + NFGEN_LEN) {
            nfq_msg m;
            parse_packet(b + NLH_LEN + NFGEN_LEN, len - NLH_LEN - NFGEN_LEN, &m);
            if (m.data) {
                npk++;
                if (cb)
                    cb(&m, ctx);
                else /* packets queued while configuring pass untouched */
                    nfq_verdict(q, m.id, NFQ_ACCEPT, NULL, 0, 0, 0);
            }
        }
        if (ALIGN4(len) >= n)
            break;
        b += ALIGN4(len);
        n -= ALIGN4(len);
    }
    return npk;
}

/* Sends a config message and waits for its acknowledgement. Returns 0 or
 * the kernel's errno. */
static int config(nfq *q, size_t len)
{
    uint32_t seq = q->seq;
    int ack = -1;
    if (msg_send(q, len) < 0)
        return errno ? errno : EIO;
    for (int tries = 0; ack < 0 && tries < 100; tries++) {
        struct pollfd pfd = {.fd = q->fd, .events = POLLIN};
        ssize_t r;
        if (poll(&pfd, 1, 2000) <= 0)
            return ETIMEDOUT;
        r = recv(q->fd, q->rx, RXBUF, 0);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ENOBUFS)
                continue;
            return errno;
        }
        dispatch(q, (size_t)r, NULL, NULL, seq, &ack);
    }
    return ack < 0 ? ETIMEDOUT : ack;
}

static int cfg_cmd(nfq *q, uint8_t cmd, uint16_t res_id, uint16_t pf)
{
    uint8_t c[4] = {cmd, 0, 0, 0};
    size_t off = msg_begin(q, NFQNL_MSG_CONFIG, NLM_F_ACK, res_id);
    put16(c + 2, htons(pf));
    off = put_attr(q, off, NFQA_CFG_CMD, c, 4);
    return config(q, off);
}

nfq *nfq_open(const nfq_config *cfg, int *errnum, sbuf *err)
{
    nfq *q = xcalloc(1, sizeof(*q));
    struct sockaddr_nl_ sa;
    uint8_t params[5];
    uint32_t v;
    size_t off;
    int e;

    *errnum = 0;
    q->queue = cfg->queue;
    q->rx = xmalloc(RXBUF);
    q->tx = xmalloc(TXBUF);
    q->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (q->fd < 0) {
        *errnum = errno;
        sb_printf(err, "netlink socket: %s%s", strerror(errno),
                  errno == EPROTONOSUPPORT ? " (kernel without nfnetlink?)" : "");
        goto fail;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(q->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        *errnum = errno;
        sb_printf(err, "netlink bind: %s", strerror(errno));
        goto fail;
    }
    if (cfg->rcvbuf > 0) {
        int sz = cfg->rcvbuf;
        if (setsockopt(q->fd, SOL_SOCKET, SO_RCVBUFFORCE, &sz, sizeof(sz)) < 0)
            setsockopt(q->fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    }
    /* Kernels before 3.8 need the protocol family bound to the queue
     * handler; newer ones ignore these commands. */
    cfg_cmd(q, NFQNL_CFG_CMD_PF_UNBIND, 0, AF_INET);
    cfg_cmd(q, NFQNL_CFG_CMD_PF_BIND, 0, AF_INET);
    cfg_cmd(q, NFQNL_CFG_CMD_PF_UNBIND, 0, AF_INET6);
    cfg_cmd(q, NFQNL_CFG_CMD_PF_BIND, 0, AF_INET6);

    e = cfg_cmd(q, NFQNL_CFG_CMD_BIND, q->queue, 0);
    if (e) {
        *errnum = e;
        sb_printf(err, "cannot bind NFQUEUE %u: %s%s", q->queue, strerror(e),
                  e == EBUSY ? " (another program owns this queue)" : "");
        goto fail;
    }
    off = msg_begin(q, NFQNL_MSG_CONFIG, NLM_F_ACK, q->queue);
    v = htonl(0xffff);
    memcpy(params, &v, 4);
    params[4] = NFQNL_COPY_PACKET;
    off = put_attr(q, off, NFQA_CFG_PARAMS, params, 5);
    e = config(q, off);
    if (e) {
        *errnum = e;
        sb_printf(err, "NFQUEUE copy mode: %s", strerror(e));
        goto fail;
    }
    if (cfg->maxlen) {
        off = msg_begin(q, NFQNL_MSG_CONFIG, NLM_F_ACK, q->queue);
        v = htonl(cfg->maxlen);
        off = put_attr(q, off, NFQA_CFG_QUEUE_MAXLEN, &v, 4);
        if ((e = config(q, off)) != 0)
            LOGW("nfq", "cannot set queue length %u: %s", cfg->maxlen, strerror(e));
    }
    if (cfg->fail_open) {
        uint32_t f = htonl(NFQA_CFG_F_FAIL_OPEN);
        off = msg_begin(q, NFQNL_MSG_CONFIG, NLM_F_ACK, q->queue);
        off = put_attr(q, off, NFQA_CFG_FLAGS, &f, 4);
        off = put_attr(q, off, NFQA_CFG_MASK, &f, 4);
        if ((e = config(q, off)) != 0) /* kernels before 3.6 */
            LOGD("nfq", "fail-open is not supported: %s", strerror(e));
    }
    return q;
fail:
    nfq_close(q);
    return NULL;
}

void nfq_close(nfq *q)
{
    if (!q)
        return;
    if (q->fd >= 0) {
        uint8_t c[4] = {NFQNL_CFG_CMD_UNBIND, 0, 0, 0};
        size_t off = msg_begin(q, NFQNL_MSG_CONFIG, 0, q->queue);
        off = put_attr(q, off, NFQA_CFG_CMD, c, 4);
        msg_send(q, off);
        close(q->fd);
    }
    free(q->rx);
    free(q->tx);
    free(q);
}

int nfq_read(nfq *q, nfq_cb cb, void *ctx, uint64_t *dropped)
{
    ssize_t r = recv(q->fd, q->rx, RXBUF, MSG_DONTWAIT);
    if (r < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ENOBUFS) { /* the kernel dropped packets for us */
            if (dropped)
                (*dropped)++;
            return 0;
        }
        return -1;
    }
    return dispatch(q, (size_t)r, cb, ctx, 0, NULL);
}

int nfq_verdict(nfq *q, uint32_t id, int verdict, const uint8_t *data, size_t len, int set_mark,
                uint32_t mark)
{
    uint32_t vh[2] = {htonl((uint32_t)verdict), htonl(id)};
    size_t off = msg_begin(q, NFQNL_MSG_VERDICT, 0, q->queue);
    off = put_attr(q, off, NFQA_VERDICT_HDR, vh, sizeof(vh));
    if (set_mark) {
        uint32_t m = htonl(mark);
        off = put_attr(q, off, NFQA_MARK, &m, 4);
    }
    if (data) {
        if (len > 65535 - 4 || off + ALIGN4(4 + len) > TXBUF) {
            errno = EMSGSIZE;
            return -1;
        }
        off = put_attr(q, off, NFQA_PAYLOAD, data, len);
    }
    return msg_send(q, off);
}

#else
typedef int nfq_unused_on_this_platform;
#endif
