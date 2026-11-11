#include "nflog.h"

#include <string.h>

/* ---- parsing (every platform: the tests) ---------------------------------- */

#define P_ALIGN4(n) (((n) + 3u) & ~3u)
#define P_NLH_LEN 16
#define P_NFGEN_LEN 4
#define P_TYPE_PACKET ((4 << 8) | 0) /* NFNL_SUBSYS_ULOG, NFULNL_MSG_PACKET */

enum { A_PACKET_HDR = 1, A_MARK = 2, A_INDEV = 4, A_OUTDEV = 5, A_PAYLOAD = 9, A_PREFIX = 10 };

/* netlink's own fields are in host order, the attributes' values big endian */
static uint32_t h32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}
static uint16_t h16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}
static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }

static void parse_packet(const uint8_t *p, size_t len, nflog_msg *m, char *prefix, size_t pcap)
{
    memset(m, 0, sizeof(*m));
    prefix[0] = 0;
    m->prefix = prefix;
    while (len >= 4) {
        uint16_t alen = h16(p), type = h16(p + 2) & 0x3fff;
        const uint8_t *d = p + 4;
        size_t dlen;
        if (alen < 4 || alen > len)
            break;
        dlen = alen - 4u;
        switch (type) {
        case A_PACKET_HDR:
            if (dlen >= 3)
                m->hook = d[2];
            break;
        case A_MARK:
            if (dlen >= 4)
                m->mark = be32(d);
            break;
        case A_INDEV:
            if (dlen >= 4)
                m->indev = be32(d);
            break;
        case A_OUTDEV:
            if (dlen >= 4)
                m->outdev = be32(d);
            break;
        case A_PAYLOAD:
            m->data = d;
            m->len = dlen;
            break;
        case A_PREFIX: {
            size_t k = 0;
            while (k < dlen && k + 1 < pcap && d[k]) {
                prefix[k] = (char)d[k];
                k++;
            }
            prefix[k] = 0;
            break;
        }
        }
        if (P_ALIGN4(alen) >= len)
            break;
        p += P_ALIGN4(alen);
        len -= P_ALIGN4(alen);
    }
}

int nflog_parse(const uint8_t *b, size_t n, nflog_cb cb, void *ctx)
{
    int npk = 0;
    while (n >= P_NLH_LEN) {
        uint32_t len = h32(b);
        uint16_t type = h16(b + 4);
        if (len < P_NLH_LEN || len > n)
            break;
        if (type == P_TYPE_PACKET && len >= P_NLH_LEN + P_NFGEN_LEN) {
            nflog_msg m;
            char prefix[64];
            parse_packet(b + P_NLH_LEN + P_NFGEN_LEN, len - P_NLH_LEN - P_NFGEN_LEN, &m, prefix, sizeof(prefix));
            if (m.data) {
                npk++;
                cb(&m, ctx);
            }
        }
        if (P_ALIGN4(len) >= n)
            break;
        b += P_ALIGN4(len);
        n -= P_ALIGN4(len);
    }
    return npk;
}


#ifdef __linux__

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "log.h"

/* Netlink and nfnetlink_log ABI (stable; no kernel headers needed) */
#ifndef AF_NETLINK
#  define AF_NETLINK 16
#endif
#define NETLINK_NETFILTER 12
#define NLMSG_ERROR 2
#define NLM_F_REQUEST 1
#define NLM_F_ACK 4

#define NFNL_SUBSYS_ULOG 4
#define NFULNL_MSG_PACKET 0
#define NFULNL_MSG_CONFIG 1

#define NFULNL_CFG_CMD_BIND 1
#define NFULNL_CFG_CMD_UNBIND 2
#define NFULNL_CFG_CMD_PF_BIND 3
#define NFULNL_CFG_CMD_PF_UNBIND 4

#define NFULA_CFG_CMD 1
#define NFULA_CFG_MODE 2
#define NFULA_CFG_TIMEOUT 4
#define NFULA_CFG_QTHRESH 5
#define NFULNL_COPY_PACKET 2

#define NFULA_PACKET_HDR 1
#define NFULA_MARK 2
#define NFULA_IFINDEX_INDEV 4
#define NFULA_IFINDEX_OUTDEV 5
#define NFULA_PAYLOAD 9
#define NFULA_PREFIX 10

#define NLA_TYPE_MASK 0x3fff

#ifndef SO_RCVBUFFORCE
#  define SO_RCVBUFFORCE 33
#endif

#define ALIGN4(n) (((n) + 3u) & ~3u)
#define NLH_LEN 16
#define NFGEN_LEN 4
#define RXBUF (65536 + 4096)
#define TXBUF 256

struct sockaddr_nl_ {
    sa_family_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

struct nflog {
    int fd;
    uint16_t group;
    uint32_t seq;
    uint8_t *rx;
    uint8_t tx[TXBUF];
};

int nflog_fd(const nflog *l) { return l->fd; }

static void put16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint16_t get16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}
static uint32_t get32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static size_t msg_begin(nflog *l, uint16_t flags, uint16_t res_id, uint8_t family)
{
    uint8_t *b = l->tx;
    memset(b, 0, NLH_LEN + NFGEN_LEN);
    put16(b + 4, (uint16_t)((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG));
    put16(b + 6, (uint16_t)(NLM_F_REQUEST | flags));
    put32(b + 8, ++l->seq);
    b[NLH_LEN] = family;
    put16(b + NLH_LEN + 2, htons(res_id));
    return NLH_LEN + NFGEN_LEN;
}

static size_t put_attr(nflog *l, size_t off, uint16_t type, const void *data, size_t len)
{
    uint8_t *b = l->tx + off;
    put16(b, (uint16_t)(4 + len));
    put16(b + 2, type);
    memcpy(b + 4, data, len);
    memset(b + 4 + len, 0, ALIGN4(4 + len) - (4 + len));
    return off + ALIGN4(4 + len);
}

/* Sends a config message and waits for its acknowledgement: 0 or errno */
static int config(nflog *l, size_t len)
{
    struct sockaddr_nl_ sa;
    uint32_t seq = l->seq;
    put32(l->tx, (uint32_t)len);
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(l->fd, l->tx, len, 0, (struct sockaddr *)&sa, sizeof(sa)) != (ssize_t)len)
        return errno ? errno : EIO;
    for (int tries = 0; tries < 100; tries++) {
        struct pollfd pfd = {.fd = l->fd, .events = POLLIN};
        const uint8_t *b = l->rx;
        ssize_t r;
        size_t n;
        if (poll(&pfd, 1, 2000) <= 0)
            return ETIMEDOUT;
        r = recv(l->fd, l->rx, RXBUF, 0);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ENOBUFS)
                continue;
            return errno;
        }
        n = (size_t)r;
        while (n >= NLH_LEN) {
            uint32_t ml = get32(b);
            if (ml < NLH_LEN || ml > n)
                break;
            if (get16(b + 4) == NLMSG_ERROR && get32(b + 8) == seq && ml >= NLH_LEN + 4) {
                int32_t e;
                memcpy(&e, b + NLH_LEN, 4);
                return -e;
            }
            if (ALIGN4(ml) >= n)
                break;
            b += ALIGN4(ml);
            n -= ALIGN4(ml);
        }
    }
    return ETIMEDOUT;
}

static int cfg_cmd(nflog *l, uint8_t cmd, uint16_t group, uint8_t family)
{
    size_t off = msg_begin(l, NLM_F_ACK, group, family);
    off = put_attr(l, off, NFULA_CFG_CMD, &cmd, 1);
    return config(l, off);
}

nflog *nflog_open(uint16_t group, uint32_t range, int rcvbuf, sbuf *err)
{
    nflog *l = xcalloc(1, sizeof(*l));
    struct sockaddr_nl_ sa;
    uint8_t mode[6];
    uint32_t v;
    size_t off;
    int e;
    l->group = group;
    l->rx = xmalloc(RXBUF);
    l->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (l->fd < 0) {
        sb_printf(err, "netlink socket: %s", strerror(errno));
        goto fail;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(l->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        sb_printf(err, "netlink bind: %s", strerror(errno));
        goto fail;
    }
    if (rcvbuf > 0 && setsockopt(l->fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0)
        setsockopt(l->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    /* kernels before 3.17 want the families bound to nfnetlink_log */
    cfg_cmd(l, NFULNL_CFG_CMD_PF_UNBIND, 0, AF_INET);
    cfg_cmd(l, NFULNL_CFG_CMD_PF_BIND, 0, AF_INET);
    cfg_cmd(l, NFULNL_CFG_CMD_PF_UNBIND, 0, AF_INET6);
    cfg_cmd(l, NFULNL_CFG_CMD_PF_BIND, 0, AF_INET6);
    if ((e = cfg_cmd(l, NFULNL_CFG_CMD_BIND, group, 0)) != 0) {
        sb_printf(err, "cannot bind NFLOG group %u: %s%s", group, strerror(e),
                  e == EBUSY ? " (another program reads this group)" : "");
        goto fail;
    }
    off = msg_begin(l, NLM_F_ACK, group, 0);
    v = htonl(range);
    memcpy(mode, &v, 4);
    mode[4] = NFULNL_COPY_PACKET;
    mode[5] = 0;
    off = put_attr(l, off, NFULA_CFG_MODE, mode, 6);
    if ((e = config(l, off)) != 0) {
        sb_printf(err, "NFLOG copy mode: %s", strerror(e));
        goto fail;
    }
    /* every packet at once (the default waits up to a second) */
    off = msg_begin(l, NLM_F_ACK, group, 0);
    v = htonl(1);
    off = put_attr(l, off, NFULA_CFG_QTHRESH, &v, 4);
    v = 0;
    off = put_attr(l, off, NFULA_CFG_TIMEOUT, &v, 4);
    if ((e = config(l, off)) != 0)
        LOGD("nflog", "cannot set the flush threshold: %s", strerror(e));
    return l;
fail:
    nflog_close(l);
    return NULL;
}

void nflog_close(nflog *l)
{
    if (!l)
        return;
    if (l->fd >= 0) {
        cfg_cmd(l, NFULNL_CFG_CMD_UNBIND, l->group, 0);
        close(l->fd);
    }
    free(l->rx);
    free(l);
}

int nflog_read(nflog *l, nflog_cb cb, void *ctx, uint64_t *lost)
{
    ssize_t r = recv(l->fd, l->rx, RXBUF, MSG_DONTWAIT);
    if (r < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        if (errno == ENOBUFS) {
            if (lost)
                (*lost)++;
            return 0;
        }
        return -1;
    }
    return nflog_parse(l->rx, (size_t)r, cb, ctx);
}

#else /* not Linux */

nflog *nflog_open(uint16_t group, uint32_t range, int rcvbuf, sbuf *err)
{
    (void)group, (void)range, (void)rcvbuf;
    sb_puts(err, "NFLOG is Linux only");
    return NULL;
}
void nflog_close(nflog *l) { (void)l; }
int nflog_fd(const nflog *l)
{
    (void)l;
    return -1;
}
int nflog_read(nflog *l, nflog_cb cb, void *ctx, uint64_t *lost)
{
    (void)l, (void)cb, (void)ctx, (void)lost;
    return -1;
}
#endif
