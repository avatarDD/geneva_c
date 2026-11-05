#include "tls.h"

#include <string.h>

typedef struct {
    const uint8_t *p;
    size_t n, off;
    int cut; /* a read went past the end */
} cur;

static int need(cur *c, size_t k)
{
    if (k > c->n - c->off) {
        c->cut = 1;
        return 0;
    }
    return 1;
}

static unsigned rd(cur *c, size_t k)
{
    unsigned v = 0;
    if (!need(c, k))
        return 0;
    for (size_t i = 0; i < k; i++)
        v = v << 8 | c->p[c->off + i];
    c->off += k;
    return v;
}

static int skip(cur *c, size_t k)
{
    if (!need(c, k))
        return 0;
    c->off += k;
    return 1;
}

static int lower_ok(int ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' ||
           ch == '.' || ch == '_' || ch == '*';
}

/* server_name extension body: list length, (type 0, length, name)... */
static int read_sni(const uint8_t *p, size_t n, char *out, size_t cap)
{
    size_t off = 2, ll;
    if (n < 2)
        return TLS_NOT_CH;
    ll = (size_t)p[0] << 8 | p[1];
    if (ll + 2 > n)
        return TLS_NOT_CH;
    while (off + 3 <= 2 + ll) {
        uint8_t type = p[off];
        size_t nl = (size_t)p[off + 1] << 8 | p[off + 2];
        off += 3;
        if (off + nl > 2 + ll)
            return TLS_NOT_CH;
        if (type == 0) {
            if (!nl || nl + 1 > cap)
                return TLS_NOT_CH;
            for (size_t i = 0; i < nl; i++)
                if (!lower_ok(p[off + i]))
                    return TLS_NOT_CH;
            memcpy(out, p + off, nl);
            out[nl] = 0;
            return TLS_SNI;
        }
        off += nl;
    }
    return TLS_NO_SNI;
}

int tls_hs_sni(const uint8_t *p, size_t n, char *out, size_t cap, size_t *msg_len)
{
    cur c = {p, n, 0, 0};
    size_t len, end, ext_end;
    if (cap)
        out[0] = 0;
    if (n < 1 || p[0] != 1)
        return TLS_NOT_CH;
    if (n < 4)
        return TLS_PARTIAL;
    c.off = 1;
    len = rd(&c, 3);
    if (msg_len)
        *msg_len = len + 4;
    if (len < 38)
        return TLS_NOT_CH;
    end = 4 + len;
    /* version, random, session id, cipher suites, compression */
    if (rd(&c, 1) != 3)
        return c.cut ? TLS_PARTIAL : TLS_NOT_CH;
    skip(&c, 1 + 32);
    skip(&c, rd(&c, 1));
    skip(&c, rd(&c, 2));
    skip(&c, rd(&c, 1));
    if (c.cut)
        return TLS_PARTIAL;
    if (c.off == end)
        return TLS_NO_SNI; /* no extensions */
    ext_end = c.off + 2 + rd(&c, 2);
    if (c.cut)
        return TLS_PARTIAL;
    if (ext_end > end)
        return TLS_NOT_CH;
    while (c.off + 4 <= ext_end) {
        unsigned type = rd(&c, 2);
        size_t el = rd(&c, 2);
        if (c.cut)
            return TLS_PARTIAL;
        if (c.off + el > ext_end)
            return TLS_NOT_CH;
        if (type == 0) {
            if (!need(&c, el))
                return TLS_PARTIAL;
            return read_sni(p + c.off, el, out, cap);
        }
        if (!skip(&c, el))
            return TLS_PARTIAL;
    }
    return TLS_NO_SNI; /* every extension seen */
}

int tls_rec_sni(const uint8_t *p, size_t n, char *out, size_t cap, uint8_t *hs, size_t hs_cap)
{
    size_t hn = 0, off = 0;
    if (cap)
        out[0] = 0;
    if (n < 1 || p[0] != 22)
        return TLS_NOT_CH;
    while (off < n) {
        size_t rl, k;
        if (p[off] != 22)
            break;
        if (n - off < 5) {
            if (!hn)
                return TLS_PARTIAL;
            break;
        }
        if (p[off + 1] != 3)
            return TLS_NOT_CH;
        rl = (size_t)p[off + 3] << 8 | p[off + 4];
        if (!rl || rl > 16384 + 256)
            return TLS_NOT_CH;
        off += 5;
        k = rl < n - off ? rl : n - off;
        if (k > hs_cap - hn)
            k = hs_cap - hn;
        memcpy(hs + hn, p + off, k);
        hn += k;
        off += k;
        if (k < rl)
            break; /* the record is cut */
    }
    if (!hn)
        return TLS_PARTIAL; /* a record header and nothing yet */
    return tls_hs_sni(hs, hn, out, cap, NULL);
}
