#include "util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void oom(void)
{
    fputs("geneva: out of memory\n", stderr);
    abort();
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        oom();
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        oom();
    return p;
}

void *xrealloc(void *p, size_t n)
{
    p = realloc(p, n ? n : 1);
    if (!p)
        oom();
    return p;
}

char *xstrdup(const char *s) { return xstrndup(s, strlen(s)); }

char *xstrndup(const char *s, size_t n)
{
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

char *xasprintf(const char *fmt, ...)
{
    sbuf b;
    va_list ap;
    sb_init(&b);
    va_start(ap, fmt);
    sb_vprintf(&b, fmt, ap);
    va_end(ap);
    return sb_take(&b);
}

/* ---- sbuf ---------------------------------------------------------------- */

void sb_init(sbuf *b)
{
    b->data = NULL;
    b->len = 0;
    b->cap = 0;
}

void sb_free(sbuf *b)
{
    free(b->data);
    sb_init(b);
}

void sb_reset(sbuf *b)
{
    b->len = 0;
    if (b->data)
        b->data[0] = 0;
}

void sb_reserve(sbuf *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    if (need <= b->cap)
        return;
    size_t cap = b->cap ? b->cap : 64;
    while (cap < need)
        cap *= 2;
    b->data = xrealloc(b->data, cap);
    b->cap = cap;
}

void sb_append(sbuf *b, const void *p, size_t n)
{
    sb_reserve(b, n);
    if (n)
        memcpy(b->data + b->len, p, n);
    b->len += n;
    b->data[b->len] = 0;
}

void sb_puts(sbuf *b, const char *s) { sb_append(b, s, strlen(s)); }

void sb_putc(sbuf *b, char c) { sb_append(b, &c, 1); }

void sb_vprintf(sbuf *b, const char *fmt, va_list ap)
{
    va_list ap2;
    int n;
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap2);
    va_end(ap2);
    if (n < 0)
        return;
    sb_reserve(b, (size_t)n);
    vsnprintf(b->data + b->len, (size_t)n + 1, fmt, ap);
    b->len += (size_t)n;
}

void sb_printf(sbuf *b, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    sb_vprintf(b, fmt, ap);
    va_end(ap);
}

char *sb_take(sbuf *b)
{
    char *p = b->data ? b->data : xstrdup("");
    sb_init(b);
    return p;
}

/* ---- strings ------------------------------------------------------------- */

int str_ieq(const char *a, const char *b)
{
    for (; *a && *b; a++, b++)
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
    return *a == *b;
}

int str_ieqn(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
        if (!a[i])
            return 1;
    }
    return 1;
}

int str_starts(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

int str_ends(const char *s, const char *suffix)
{
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && memcmp(s + a - b, suffix, b) == 0;
}

int parse_i64(const char *s, int64_t *out)
{
    char *end;
    long long v;
    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtoll(s, &end, 10);
    if (errno || *end)
        return -1;
    *out = (int64_t)v;
    return 0;
}

int parse_u64(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;
    if (!s || !*s || *s == '-')
        return -1;
    errno = 0;
    v = strtoull(s, &end, 0);
    if (errno || *end)
        return -1;
    *out = (uint64_t)v;
    return 0;
}

int parse_double(const char *s, double *out)
{
    char *end;
    double v;
    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtod(s, &end);
    if (errno || *end)
        return -1;
    *out = v;
    return 0;
}

void url_quote(sbuf *out, const uint8_t *p, size_t n)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < n; i++) {
        uint8_t c = p[i];
        if (isalnum(c) || c == '_' || c == '.' || c == '-' || c == '~' || c == '/') {
            sb_putc(out, (char)c);
        } else {
            char e[3] = {'%', hex[c >> 4], hex[c & 15]};
            sb_append(out, e, 3);
        }
    }
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

size_t url_unquote(const char *s, uint8_t *out)
{
    size_t n = 0;
    while (*s) {
        if (s[0] == '%' && hexval(s[1]) >= 0 && hexval(s[2]) >= 0) {
            out[n++] = (uint8_t)(hexval(s[1]) * 16 + hexval(s[2]));
            s += 3;
        } else {
            out[n++] = (uint8_t)*s++;
        }
    }
    return n;
}

void hex_encode(sbuf *out, const uint8_t *p, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    sb_reserve(out, n * 2);
    for (size_t i = 0; i < n; i++) {
        out->data[out->len++] = hex[p[i] >> 4];
        out->data[out->len++] = hex[p[i] & 15];
    }
    out->data[out->len] = 0;
}

long hex_decode(const char *s, uint8_t *out, size_t cap)
{
    size_t n = strlen(s);
    if (n % 2 || n / 2 > cap)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
    return (long)(n / 2);
}

char *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    sbuf b;
    char tmp[4096];
    size_t n;
    if (!f)
        return NULL;
    sb_init(&b);
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
        sb_append(&b, tmp, n);
    if (ferror(f)) {
        fclose(f);
        sb_free(&b);
        return NULL;
    }
    fclose(f);
    if (len)
        *len = b.len;
    return sb_take(&b);
}

int write_file(const char *path, const void *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        return -1;
    }
    return fclose(f) == 0 ? 0 : -1;
}
