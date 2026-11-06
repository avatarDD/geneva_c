#include "rawsend.h"

#ifdef __linux__

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#ifndef SO_MARK
#  define SO_MARK 36
#endif
#ifndef IP_NODEFRAG
#  define IP_NODEFRAG 22
#endif
#ifndef IP_FREEBIND
#  define IP_FREEBIND 15
#endif
#ifndef IPV6_FREEBIND
#  define IPV6_FREEBIND 78
#endif
#ifndef SO_BINDTODEVICE
#  define SO_BINDTODEVICE 25
#endif

struct rawsend {
    int fd4, fd6;
    uint32_t mark;            /* the engine's own */
    uint32_t cur4, cur6;      /* the mark set on each socket now */
    char dev4[16], dev6[16];  /* the device each is bound to now */
};

static unsigned g_flags;

void rawsend_set_flags(unsigned flags) { g_flags = flags; }

static int open_one(int family, uint32_t mark, sbuf *err)
{
    int fd = socket(family, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW), one = 1;
    if (fd < 0) {
        sb_printf(err, "%sraw socket (IPv%d): %s", err->len ? "; " : "",
                  family == AF_INET ? 4 : 6, strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        sb_printf(err, "%sSO_MARK: %s", err->len ? "; " : "", strerror(errno));
        close(fd);
        return -1;
    }
    /* IP fragments we send must not be reassembled by conntrack (2.6.36+) */
    if (family == AF_INET)
        setsockopt(fd, IPPROTO_IP, IP_NODEFRAG, &one, sizeof(one));
    if (g_flags & RAWSEND_EXT) {
        int pri = 6;
        /* nfqws2 fails on these but for IPV6_FREEBIND (Linux 4.15+); here
         * they only help */
        setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &pri, sizeof(pri));
        if (family == AF_INET)
            setsockopt(fd, IPPROTO_IP, IP_FREEBIND, &one, sizeof(one));
        else
            setsockopt(fd, IPPROTO_IPV6, IPV6_FREEBIND, &one, sizeof(one));
    }
    return fd;
}

rawsend *rawsend_open(uint32_t mark, sbuf *err)
{
    rawsend *r = xcalloc(1, sizeof(*r));
    r->fd4 = open_one(AF_INET, mark, err);
    r->fd6 = open_one(AF_INET6, mark, err);
    r->mark = r->cur4 = r->cur6 = mark;
    if (r->fd4 < 0 && r->fd6 < 0) {
        free(r);
        return NULL;
    }
    return r;
}

void rawsend_close(rawsend *r)
{
    if (!r)
        return;
    if (r->fd4 >= 0)
        close(r->fd4);
    if (r->fd6 >= 0)
        close(r->fd6);
    free(r);
}

static int send_raw(rawsend *r, const uint8_t *pkt, size_t len);

/* The socket's mark and device as asked; 0 or -1 */
static int prepare(int fd, uint32_t *cur, char *dev, uint32_t mark, const char *ifout, int bind)
{
    if (*cur != mark) {
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0)
            return -1;
        *cur = mark;
    }
    if (bind) {
        const char *want = ifout ? ifout : "";
        if (strncmp(dev, want, 15)) {
            if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, want, (socklen_t)(*want ? strlen(want) + 1 : 0)) < 0)
                return -1;
            strncpy(dev, want, 15);
            dev[15] = 0;
        }
    }
    return 0;
}

int rawsend_send_x(rawsend *r, const uint8_t *pkt, size_t len, uint32_t mark, const char *ifout)
{
    int v6 = len >= 1 && (pkt[0] >> 4) == 6;
    int fd = v6 ? r->fd6 : r->fd4;
    if (fd >= 0 && prepare(fd, v6 ? &r->cur6 : &r->cur4, v6 ? r->dev6 : r->dev4, r->mark | mark, ifout,
                           (g_flags & (v6 ? RAWSEND_BIND6 : RAWSEND_BIND4)) != 0) < 0)
        return -1;
    return send_raw(r, pkt, len);
}

int rawsend_send(rawsend *r, const uint8_t *pkt, size_t len) { return rawsend_send_x(r, pkt, len, 0, NULL); }

static int send_raw(rawsend *r, const uint8_t *pkt, size_t len)
{
    ssize_t n;
    if (len >= 20 && (pkt[0] >> 4) == 4) {
        struct sockaddr_in sa;
        if (r->fd4 < 0) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        memcpy(&sa.sin_addr, pkt + 16, 4);
        do
            n = sendto(r->fd4, pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa));
        while (n < 0 && errno == EINTR);
    } else if (len >= 40 && (pkt[0] >> 4) == 6) {
        struct sockaddr_in6 sa;
        if (r->fd6 < 0) {
            errno = EAFNOSUPPORT;
            return -1;
        }
        memset(&sa, 0, sizeof(sa));
        sa.sin6_family = AF_INET6;
        memcpy(&sa.sin6_addr, pkt + 24, 16);
        do
            n = sendto(r->fd6, pkt, len, 0, (struct sockaddr *)&sa, sizeof(sa));
        while (n < 0 && errno == EINTR);
    } else {
        errno = EINVAL;
        return -1;
    }
    return n == (ssize_t)len ? 0 : -1;
}

#else
typedef int rawsend_unused_on_this_platform;
#endif
