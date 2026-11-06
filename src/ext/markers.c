/*
 * Ported from zapret2 nfq2/protocol.c and lua.c (MIT License, Copyright (c)
 * bol-van; the notice is in docs/EXT.md).
 */
#include "markers.h"

#include <stdlib.h>
#include <string.h>

#include "l7.h"

static const char *const names[PM_LAST] = {"abs", "host", "endhost", "sld", "midsld", "endsld", "method", "extlen",
                                           "sniext"};

/* a signed decimal that fits int16 ("+5", "-1", "7"); strict, unlike atoi */
static int int16_parse(const char *s, size_t n, int16_t *v)
{
    long x = 0;
    size_t i = 0;
    int neg = 0;
    if (i < n && (s[i] == '+' || s[i] == '-'))
        neg = s[i++] == '-';
    if (i == n)
        return -1;
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return -1;
        x = x * 10 + (s[i] - '0');
        if (x > 32768)
            return -1;
    }
    if (neg)
        x = -x;
    if (x < -32768 || x > 32767)
        return -1;
    *v = (int16_t)x;
    return 0;
}

static int parse_n(const char *s, size_t n, xmarker *m)
{
    size_t k;
    if (!int16_parse(s, n, &m->pos)) {
        m->marker = PM_ABS;
        return 0;
    }
    for (k = 0; k < n && s[k] != '+' && s[k] != '-'; k++)
        ;
    for (int i = 0; i < PM_LAST; i++)
        if (strlen(names[i]) == k && !memcmp(names[i], s, k)) {
            m->marker = (uint8_t)i;
            m->pos = 0;
            return k == n ? 0 : int16_parse(s + k, n - k, &m->pos);
        }
    return -1;
}

int xmarker_parse(const char *s, xmarker *m) { return parse_n(s, strlen(s), m); }

int xmarker_list_parse(const char *s, xmarker *m, int max, sbuf *err)
{
    int k = 0;
    const char *p = s;
    if (!*s)
        return 0;
    for (;;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (k >= max) {
            sb_printf(err, "too many positions in \"%s\" (at most %d)", s, max);
            return -1;
        }
        if (parse_n(p, n, &m[k]) < 0) {
            sb_printf(err, "bad position \"%.*s\" (a number, or host, endhost, sld, midsld, endsld, method, "
                           "extlen, sniext with an optional +N/-N)",
                      (int)n, p);
            return -1;
        }
        k++;
        if (!e)
            return k;
        p = e + 1;
    }
}

void xmarker_print(const xmarker *m, sbuf *out)
{
    if (m->marker == PM_ABS)
        sb_printf(out, "%d", m->pos);
    else if (m->pos)
        sb_printf(out, "%s%+d", names[m->marker], m->pos);
    else
        sb_puts(out, names[m->marker]);
}

static long check(size_t n, long off) { return off >= 0 && (size_t)off < n ? off : -1; }

static long any_pos(const xmarker *m, size_t n)
{
    if (m->marker != PM_ABS)
        return -1;
    return check(n, m->pos < 0 ? (long)n + m->pos : m->pos);
}

static long host_pos(const xmarker *m, const uint8_t *d, size_t n, size_t ho, size_t hl)
{
    const uint8_t *p;
    size_t sl;
    long off;
    switch (m->marker) {
    case PM_HOST:
        off = (long)ho + m->pos;
        break;
    case PM_HOST_END:
        off = (long)(ho + hl) + m->pos;
        break;
    case PM_HOST_SLD:
    case PM_HOST_MIDSLD:
    case PM_HOST_ENDSLD:
        if (ho + hl > n || !l7_find_nld(d + ho, hl, 2, &p, &sl))
            return -1;
        off = m->marker == PM_HOST_SLD      ? p - d
              : m->marker == PM_HOST_ENDSLD ? (long)(p - d) + (long)sl
              : sl == 1                     ? p + 1 - d
                                            : (long)(p - d) + (long)(sl / 2);
        off += m->pos;
        break;
    default:
        return -1;
    }
    return check(n, off);
}

static long http_pos(const xmarker *m, const uint8_t *d, size_t n)
{
    const uint8_t *meth, *p;
    size_t ho, hl, i;
    switch (m->marker) {
    case PM_HTTP_METHOD:
        /* tpws hacks before the method: up to two \r or \n */
        if (n < 12)
            return -1;
        meth = d;
        if (*meth == '\n' || *meth == '\r')
            meth++;
        if (*meth == '\n' || *meth == '\r')
            meth++;
        for (p = meth, i = 0; i < 9 && *p >= 'A' && *p <= 'Z'; i++, p++)
            ;
        if (i < 3 || *p != ' ')
            return -1;
        return check(n, (long)(meth - d) + m->pos);
    case PM_HOST:
    case PM_HOST_END:
    case PM_HOST_SLD:
    case PM_HOST_MIDSLD:
    case PM_HOST_ENDSLD:
        for (i = 0; i + 6 <= n; i++)
            if (d[i] == '\n' && (d[i + 1] | 0x20) == 'h' && (d[i + 2] | 0x20) == 'o' &&
                (d[i + 3] | 0x20) == 's' && (d[i + 4] | 0x20) == 't' && d[i + 5] == ':')
                break;
        if (i + 6 > n || i + 1 + 7 >= n)
            return -1;
        ho = i + 1 + 5;
        if (d[ho] == ' ' || d[ho] == '\t')
            ho++;
        hl = 0;
        if (m->marker != PM_HOST)
            while (ho + hl < n && d[ho + hl] != '\r' && d[ho + hl] != '\n')
                hl++;
        return host_pos(m, d, n, ho, hl);
    default:
        return any_pos(m, n);
    }
}

static long tls_pos(const xmarker *m, const uint8_t *d, size_t n)
{
    const uint8_t *ext;
    size_t el, sl, off;
    switch (m->marker) {
    case PM_HOST:
    case PM_HOST_END:
    case PM_HOST_SLD:
    case PM_HOST_MIDSLD:
    case PM_HOST_ENDSLD:
    case PM_SNI_EXT:
        if (!l7_tls_find_ext(d, n, 0, &ext, &el, 1))
            return -1;
        if (m->marker == PM_SNI_EXT)
            return check(n, (long)(ext - d) + m->pos);
        if (!l7_tls_sni_host(&ext, &el, &sl))
            return -1;
        return host_pos(m, d, n, (size_t)(ext - d), sl);
    case PM_EXT_LEN:
        return l7_tls_ext_len_off(d, n, &off) ? check(n, (long)off + m->pos) : -1;
    default:
        return any_pos(m, n);
    }
}

long xmarker_resolve(const uint8_t *d, size_t n, int l7p, const xmarker *m)
{
    if (l7p == L7P_HTTP_REQ)
        return http_pos(m, d, n);
    if (l7p == L7P_TLS_CLIENT_HELLO)
        return tls_pos(m, d, n);
    return any_pos(m, n);
}

static int cmp_long(const void *a, const void *b)
{
    long x = *(const long *)a, y = *(const long *)b;
    return x < y ? -1 : x > y;
}

int xmarker_resolve_list(const uint8_t *d, size_t n, int l7p, const xmarker *m, int nm, long *pos)
{
    int k = 0, u = 0;
    for (int i = 0; i < nm; i++)
        if ((pos[k] = xmarker_resolve(d, n, l7p, &m[i])) >= 0)
            k++;
    qsort(pos, (size_t)k, sizeof(*pos), cmp_long);
    for (int i = 0; i < k; i++)
        if (!u || pos[u - 1] != pos[i])
            pos[u++] = pos[i];
    return u;
}

int xmarker_resolve_range(const uint8_t *d, size_t n, int l7p, const xmarker *m, int nm, int strict, long *from,
                          long *to)
{
    long a, b;
    if (nm != 2)
        return -1;
    a = xmarker_resolve(d, n, l7p, &m[0]);
    b = xmarker_resolve(d, n, l7p, &m[1]);
    if ((a < 0 && b < 0) || (strict && (a < 0 || b < 0)))
        return -1;
    if (a < 0)
        a = 0;
    if (b < 0)
        b = (long)n - 1;
    if (a > b)
        return -1;
    *from = a;
    *to = b;
    return 0;
}
