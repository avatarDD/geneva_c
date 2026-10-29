/* Small allocation, string and byte-buffer helpers used everywhere. */
#ifndef GENEVA_UTIL_H
#define GENEVA_UTIL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#if defined(__MINGW32__)
#  define PRINTF_LIKE(f, a) __attribute__((format(gnu_printf, f, a)))
#  define UNUSED __attribute__((unused))
#elif defined(__GNUC__) || defined(__clang__)
#  define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#  define UNUSED __attribute__((unused))
#else
#  define PRINTF_LIKE(f, a)
#  define UNUSED
#endif

/* Allocation helpers abort on OOM: there is no sane recovery mid-packet. */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);
char *xasprintf(const char *fmt, ...) PRINTF_LIKE(1, 2);

/* Growable byte/string buffer. data is always NUL-terminated. */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} sbuf;

void sb_init(sbuf *b);
void sb_free(sbuf *b);
void sb_reset(sbuf *b);
void sb_reserve(sbuf *b, size_t extra);
void sb_append(sbuf *b, const void *p, size_t n);
void sb_puts(sbuf *b, const char *s);
void sb_putc(sbuf *b, char c);
void sb_printf(sbuf *b, const char *fmt, ...) PRINTF_LIKE(2, 3);
void sb_vprintf(sbuf *b, const char *fmt, va_list ap);
/* Detaches the buffer; caller frees. */
char *sb_take(sbuf *b);

/* Case-insensitive ASCII comparisons (locale independent). */
int str_ieq(const char *a, const char *b);
int str_ieqn(const char *a, const char *b, size_t n);
int str_starts(const char *s, const char *prefix);
int str_ends(const char *s, const char *suffix);
/* Strict integer parsing: whole string must be consumed. Returns 0 on success. */
int parse_i64(const char *s, int64_t *out);
int parse_u64(const char *s, uint64_t *out);
int parse_double(const char *s, double *out);
/* Python-like percent encoding (urllib.parse.quote with safe='/'). */
void url_quote(sbuf *out, const uint8_t *p, size_t n);
/* Inverse of url_quote; returns decoded length. out must hold strlen(s). */
size_t url_unquote(const char *s, uint8_t *out);
void hex_encode(sbuf *out, const uint8_t *p, size_t n);
/* Returns decoded length or -1 on bad input. */
long hex_decode(const char *s, uint8_t *out, size_t cap);

/* Read a whole file; returns NULL on error. *len gets the size. */
char *read_file(const char *path, size_t *len);
int write_file(const char *path, const void *data, size_t len);

#endif
