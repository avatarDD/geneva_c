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

struct rawsend {
    int fd4, fd6;
};

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
    return fd;
}

rawsend *rawsend_open(uint32_t mark, sbuf *err)
{
    rawsend *r = xcalloc(1, sizeof(*r));
    r->fd4 = open_one(AF_INET, mark, err);
    r->fd6 = open_one(AF_INET6, mark, err);
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

int rawsend_send(rawsend *r, const uint8_t *pkt, size_t len)
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
