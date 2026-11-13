/*
 * "geneva resolve --ext" and "geneva ip2net --ext" (tools.h): ports of
 * zapret2's mdig/mdig.c and ip2net/ip2net.c, same input, output and
 * defaults. The differences are the option syntax (geneva's --name VALUE)
 * and the exit codes (geneva's).
 */
#include "tools.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "args.h"
#include "geneva.h"
#include "plat.h"
#include "probe.h"
#include "util.h"

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#else
#  include <netdb.h>
#endif

/* ---- ip2net ------------------------------------------------------------------------- */

#define V4_PCTMULT 3
#define V4_PCTDIV 4
#define V4_ZCT_MAX 10 /* /22 */
#define V4_ZCT_MIN 2  /* /30 */
#define V6_ZCT_MAX 72 /* /56 */
#define V6_ZCT_MIN 64 /* /64 */
#define V6_THRESHOLD 5

int xip2net_init(xip2net_cfg *c, int v6, const char *plen, const char *v4thr, const char *v6thr, sbuf *err)
{
    uint32_t p1 = (uint32_t)-1, p2 = (uint32_t)-1;
    int i;
    memset(c, 0, sizeof(*c));
    c->v6 = v6;
    c->pctmult = V4_PCTMULT;
    c->pctdiv = V4_PCTDIV;
    c->v6_threshold = V6_THRESHOLD;
    if (plen) {
        i = sscanf(plen, "%u-%u", &p1, &p2);
        if (i == 1)
            p2 = p1;
        if (i <= 0 || p2 < p1 || !p1 || !p2) {
            sb_printf(err, "invalid parameter for prefix-length : %s", plen);
            return -1;
        }
    }
    if (v4thr) {
        i = sscanf(v4thr, "%u/%u", &c->pctmult, &c->pctdiv);
        if (i != 2 || c->pctdiv < 2 || c->pctmult < 1 || c->pctmult >= c->pctdiv) {
            sb_printf(err, "invalid parameter for v4-threshold : %s", v4thr);
            return -1;
        }
    }
    if (v6thr) {
        i = sscanf(v6thr, "%u", &c->v6_threshold);
        if (i != 1 || c->v6_threshold < 1) {
            sb_printf(err, "invalid parameter for v6-threshold : %s", v6thr);
            return -1;
        }
    }
    if (p1 != (uint32_t)-1 && ((!v6 && (p1 > 31 || p2 > 31)) || (v6 && (p1 > 127 || p2 > 127)))) {
        sb_puts(err, "invalid parameter for prefix-length");
        return -1;
    }
    c->zct_min = v6 ? (p2 == (uint32_t)-1 ? V6_ZCT_MIN : 128 - p2) : (p2 == (uint32_t)-1 ? V4_ZCT_MIN : 32 - p2);
    c->zct_max = v6 ? (p1 == (uint32_t)-1 ? V6_ZCT_MAX : 128 - p1) : (p1 == (uint32_t)-1 ? V4_ZCT_MAX : 32 - p1);
    return 0;
}

/* the next line as zapret2's fgets(str, 256) sees it: at most 255 bytes,
 * the newline kept */
static size_t next_line(const char *text, size_t n, size_t *pos, char *line)
{
    size_t k = 0;
    while (*pos < n && k < 255) {
        char ch = text[(*pos)++];
        line[k++] = ch;
        if (ch == '\n')
            break;
    }
    line[k] = 0;
    return k;
}

static void rtrim(char *s)
{
    for (char *p = s + strlen(s) - 1; p >= s && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t'); p--)
        *p = 0;
}

static int cmp4(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static int cmp6(const void *a, const void *b) { return memcmp(a, b, 16); }

static uint32_t mask4(uint32_t zct) { return zct < 32 ? ~((1u << zct) - 1) : 0; }

static void mask6(uint32_t zct, uint8_t m[16])
{
    if (zct >= 128) {
        memset(m, 0, 16);
    } else {
        int n = (int)((127 - zct) >> 3);
        memset(m, 0xff, (size_t)n);
        memset(m + n, 0, (size_t)(16 - n));
        m[n] = (uint8_t)~((1u << (zct & 7)) - 1);
    }
}

static void and6(const uint8_t *a, const uint8_t *m, uint8_t *r)
{
    for (int i = 0; i < 16; i++)
        r[i] = a[i] & m[i];
}

static void ip2net6(const xip2net_cfg *c, const char *text, size_t n, sbuf *out)
{
    char str[256], s6[64];
    size_t pos = 0, ct = 0, cap = 0, i = 0;
    uint8_t(*v)[16] = NULL;
    while (next_line(text, n, &pos, str)) {
        char *s, d = 0;
        uint8_t a[16];
        uint32_t zct;
        rtrim(str);
        if ((s = strchr(str, '/')) || (s = strchr(str, '-'))) {
            d = *s;
            *s = 0;
        }
        if (inet_pton(AF_INET6, str, a) != 1)
            continue;
        if (d == '/') {
            if (sscanf(s + 1, "%u", &zct) == 1 && zct != 128) {
                if (zct < 128)
                    sb_printf(out, "%s/%u\n", str, zct);
                continue;
            }
        } else if (d == '-') {
            uint8_t b[16];
            if (inet_pton(AF_INET6, s + 1, b) == 1)
                sb_printf(out, "%s-%s\n", str, s + 1);
            continue;
        }
        if (ct == cap) {
            cap = cap ? cap * 2 : 1024;
            v = xrealloc(v, cap * 16);
        }
        memcpy(v[ct++], a, 16);
    }
    if (ct)
        qsort(v, ct, 16, cmp6);
    {
        size_t u = 0;
        for (size_t j = 0; j < ct; u++) {
            size_t k = j++;
            while (j < ct && !memcmp(v[j], v[k], 16))
                j++;
            memmove(v[u], v[k], 16);
        }
        ct = u;
    }
    while (i < ct) {
        uint8_t m[16], start[16], ip[16];
        uint32_t best_ct = 0, best_zct = 0, zct, ipc;
        size_t end = i + 1, p;
        for (zct = c->zct_max; zct >= c->zct_min; zct--) {
            mask6(zct, m);
            and6(v[i], m, start);
            for (p = i + 1, ipc = 1; p < ct; p++, ipc++) {
                and6(v[p], m, ip);
                if (memcmp(start, ip, 16))
                    break;
            }
            if (ipc == 1)
                break;
            if (ipc >= c->v6_threshold) {
                /* a smaller subnet with as many: no carpet bombing */
                if (!best_ct || ipc == best_ct) {
                    best_ct = ipc;
                    best_zct = zct;
                    end = p;
                } else {
                    break;
                }
            }
        }
        if (best_zct) {
            mask6(best_zct, m);
            and6(v[i], m, start);
        } else {
            memcpy(start, v[i], 16);
            end = i + 1;
        }
        inet_ntop(AF_INET6, start, s6, sizeof(s6));
        if (best_zct)
            sb_printf(out, "%s/%u\n", s6, 128 - best_zct);
        else
            sb_printf(out, "%s\n", s6);
        i = end;
    }
    free(v);
}

static void ip2net4(const xip2net_cfg *c, const char *text, size_t n, sbuf *out)
{
    char str[256];
    size_t pos = 0, ct = 0, cap = 0, i = 0;
    uint32_t *v = NULL;
    while (next_line(text, n, &pos, str)) {
        unsigned u1, u2, u3, u4, u11, u22, u33, u44, zct;
        int k;
        if ((k = sscanf(str, "%u.%u.%u.%u-%u.%u.%u.%u", &u1, &u2, &u3, &u4, &u11, &u22, &u33, &u44)) >= 8 &&
            !((u1 | u2 | u3 | u4 | u11 | u22 | u33 | u44) & 0xFFFFFF00u)) {
            sb_printf(out, "%u.%u.%u.%u-%u.%u.%u.%u\n", u1, u2, u3, u4, u11, u22, u33, u44);
        } else if ((k = sscanf(str, "%u.%u.%u.%u/%u", &u1, &u2, &u3, &u4, &zct)) >= 4 &&
                   !((u1 | u2 | u3 | u4) & 0xFFFFFF00u)) {
            if (k == 5 && zct != 32) {
                /* a subnet as it is when valid */
                if (zct < 32)
                    sb_printf(out, "%u.%u.%u.%u/%u\n", u1, u2, u3, u4, zct);
            } else {
                if (ct == cap) {
                    cap = cap ? cap * 2 : 4096;
                    v = xrealloc(v, cap * sizeof(*v));
                }
                v[ct++] = (uint32_t)u1 << 24 | (uint32_t)u2 << 16 | (uint32_t)u3 << 8 | (uint32_t)u4;
            }
        }
    }
    if (ct)
        qsort(v, ct, sizeof(*v), cmp4);
    {
        size_t u = 0;
        for (size_t j = 0; j < ct; u++) {
            uint32_t x = v[j++];
            while (j < ct && v[j] == x)
                j++;
            v[u] = x;
        }
        ct = u;
    }
    while (i < ct) {
        uint32_t mask, start, end_ip, sub, best_ct = 0, best_zct = 0, zct, ipc;
        size_t end = i + 1, p;
        for (zct = c->zct_max; zct >= c->zct_min; zct--) {
            mask = mask4(zct);
            start = v[i] & mask;
            sub = ~mask + 1;
            /* the address is in the top (1-PCT): not enough */
            if (v[i] > start + sub * (c->pctdiv - c->pctmult) / c->pctdiv)
                continue;
            end_ip = start | ~mask;
            for (p = i + 1, ipc = 1; p < ct && v[p] <= end_ip; p++)
                ipc++;
            if (ipc == 1)
                break;
            if (ipc >= sub * c->pctmult / c->pctdiv) {
                if (!best_ct || ipc == best_ct) {
                    best_ct = ipc;
                    best_zct = zct;
                    end = p;
                } else {
                    break;
                }
            }
        }
        if (best_zct) {
            start = v[i] & mask4(best_zct);
        } else {
            start = v[i];
            end = i + 1;
        }
        sb_printf(out, "%u.%u.%u.%u", start >> 24, start >> 16 & 0xff, start >> 8 & 0xff, start & 0xff);
        if (best_zct)
            sb_printf(out, "/%u", 32 - best_zct);
        sb_putc(out, '\n');
        i = end;
    }
    free(v);
}

void xip2net(const xip2net_cfg *c, const char *text, size_t n, sbuf *out)
{
    if (c->v6)
        ip2net6(c, text, n, out);
    else
        ip2net4(c, text, n, out);
}

/* the whole of a stream; -1 on a read error */
static int read_all(FILE *fp, sbuf *b)
{
    char buf[65536];
    size_t r;
    while ((r = fread(buf, 1, sizeof(buf), fp)) > 0)
        sb_append(b, buf, r);
    return ferror(fp) ? -1 : 0;
}

int xcmd_ip2net(int argc, char **argv)
{
    static const optdef defs[] = {
        {"ext", 0, 0, NULL, "turn on the extensions (required)"},
        {"4", '4', 0, NULL, "an IPv4 list (default)"},
        {"6", '6', 0, NULL, "an IPv6 list"},
        {"prefix-length", 0, 1, "MIN[-MAX]", "prefix lengths searched (default 22-30 for IPv4, 56-64 for IPv6)"},
        {"v4-threshold", 0, 1, "MUL/DIV", "IPv4: a subnet needs more than MUL/DIV of its addresses (default 3/4)"},
        {"v6-threshold", 0, 1, "N", "IPv6: a subnet needs at least N addresses (default 5)"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    xip2net_cfg c;
    sbuf in, out, e;
    int rc = EXIT_OK;
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva ip2net: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva ip2net --ext [-4|-6] [options] < LIST > NETS\n"
                  "Groups the addresses of a list (one per line) into subnets, as zapret2's\n"
                  "ip2net: the smallest subnet that holds enough of them; subnets (A/N) and\n"
                  "ranges (A-B) go out as they are, first.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (!arg_has(&a, "ext")) {
        fprintf(stderr, "geneva ip2net: needs --ext\n");
        args_free(&a);
        return EXIT_USAGE;
    }
    sb_init(&e);
    if (xip2net_init(&c, arg_has(&a, "6"), arg_str(&a, "prefix-length", NULL), arg_str(&a, "v4-threshold", NULL),
                    arg_str(&a, "v6-threshold", NULL), &e) < 0) {
        fprintf(stderr, "geneva ip2net: %s\n", e.data);
        sb_free(&e);
        args_free(&a);
        return EXIT_USAGE;
    }
    sb_free(&e);
    args_free(&a);
    sb_init(&in);
    sb_init(&out);
    if (read_all(stdin, &in) < 0) {
        fprintf(stderr, "geneva ip2net: cannot read the list\n");
        rc = EXIT_IO;
    } else {
        xip2net(&c, in.data ? in.data : "", in.len, &out);
        if (out.len && fwrite(out.data, 1, out.len, stdout) != out.len)
            rc = EXIT_IO;
    }
    sb_free(&in);
    sb_free(&out);
    return rc;
}

/* ---- resolve (mdig) ----------------------------------------------------------------- */

#define EAGAIN_TRIES 10
#define EAGAIN_DELAY 500
#define FAM4 1
#define FAM6 2

static struct {
    int verbose, family, eagain, eagain_delay, stats_every, stats_ct, stats_ok;
    time_t start;
    plat_mutex_t flock, slock;
    FILE *f_ok, *f_fail;
} gr;

static const char *eai_str(int r)
{
    static const struct {
        int code;
        const char *name;
    } t[] = {
        {EAI_NONAME, "EAI_NONAME"},
        {EAI_AGAIN, "EAI_AGAIN"},
#ifdef EAI_ADDRFAMILY
        {EAI_ADDRFAMILY, "EAI_ADDRFAMILY"},
#endif
#ifdef EAI_NODATA
        {EAI_NODATA, "EAI_NODATA"},
#endif
        {EAI_BADFLAGS, "EAI_BADFLAGS"},
        {EAI_FAIL, "EAI_FAIL"},
        {EAI_MEMORY, "EAI_MEMORY"},
        {EAI_FAMILY, "EAI_FAMILY"},
        {EAI_SERVICE, "EAI_SERVICE"},
        {EAI_SOCKTYPE, "EAI_SOCKTYPE"},
#ifdef EAI_SYSTEM
        {EAI_SYSTEM, "EAI_SYSTEM"},
#endif
    };
    for (size_t i = 0; i < ARRAY_LEN(t); i++)
        if (t[i].code == r)
            return t[i].name;
    return "UNKNOWN";
}

static int dom_valid(const char *d)
{
    if (!d || *d == '.')
        return 0;
    for (; *d; d++)
        if (!(*d == '.' || *d == '-' || *d == '_' || (*d >= '0' && *d <= '9') || (*d >= 'a' && *d <= 'z') ||
              (*d >= 'A' && *d <= 'Z')))
            return 0;
    return 1;
}

static void locked_printf(FILE *fp, const char *fmt, ...) PRINTF_LIKE(2, 3);
static void locked_printf(FILE *fp, const char *fmt, ...)
{
    va_list ap;
    if (!fp)
        return;
    va_start(ap, fmt);
    plat_mutex_lock(&gr.flock);
    vfprintf(fp, fmt, ap);
    plat_mutex_unlock(&gr.flock);
    va_end(ap);
}

#define VLOG(tid, ...)                                                                                               \
    do {                                                                                                             \
        if (gr.verbose) {                                                                                            \
            char m_[512];                                                                                            \
            snprintf(m_, sizeof(m_), __VA_ARGS__);                                                                   \
            locked_printf(stderr, "[%d] %s\n", tid, m_);                                                             \
        }                                                                                                            \
    } while (0)

static int next_name(char *dom, size_t cap)
{
    char *s;
    plat_mutex_lock(&gr.flock);
    s = fgets(dom, (int)cap, stdin);
    plat_mutex_unlock(&gr.flock);
    if (!s)
        return 0;
    rtrim(dom);
    return 1;
}

static void stat_print(int ct, int ok)
{
    if (gr.stats_every > 0) {
        time_t tm = time(NULL) - gr.start;
        locked_printf(stderr, "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d\n",
                      (unsigned)(tm / 3600), (unsigned)(tm / 60 % 60), (unsigned)(tm % 60), ct, ok, ct - ok);
    }
}

static void stat_plus(int ok)
{
    int ct, cok;
    if (gr.stats_every <= 0)
        return;
    plat_mutex_lock(&gr.slock);
    ct = ++gr.stats_ct;
    cok = gr.stats_ok += ok;
    plat_mutex_unlock(&gr.slock);
    if (!(ct % gr.stats_every))
        stat_print(ct, cok);
}

static void print_ai(const struct addrinfo *ai)
{
    char s[64];
    for (; ai; ai = ai->ai_next) {
        const void *p = ai->ai_family == AF_INET    ? (const void *)&((const struct sockaddr_in *)ai->ai_addr)->sin_addr
                        : ai->ai_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)ai->ai_addr)->sin6_addr
                                                    : NULL;
        if (p && inet_ntop(ai->ai_family, p, s, sizeof(s)))
            locked_printf(stdout, "%s\n", s);
    }
}

static void resolver(void *arg)
{
    int tid = (int)(size_t)arg;
    char dom[256];
    struct addrinfo hints;
    VLOG(tid, "started");
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = gr.family == FAM4 ? AF_INET : gr.family == FAM6 ? AF_INET6 : AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    while (next_name(dom, sizeof(dom))) {
        int ok = 0;
        if (*dom) {
            char ip[sizeof(dom)], *mask;
            uint8_t b[16];
            int fam = 0;
            snprintf(ip, sizeof(ip), "%s", dom);
            if ((mask = strchr(ip, '/')))
                *mask++ = 0;
            if (inet_pton(AF_INET, ip, b) == 1)
                fam = AF_INET;
            else if (inet_pton(AF_INET6, ip, b) == 1)
                fam = AF_INET6;
            if (fam) {
                /* an address or a subnet of the family: as it is */
                if ((fam == AF_INET && (gr.family & FAM4)) || (fam == AF_INET6 && (gr.family & FAM6))) {
                    unsigned m = 0;
                    int need = 0;
                    if (mask) {
                        if (sscanf(mask, "%u", &m) == 1) {
                            unsigned all = fam == AF_INET ? 32 : 128;
                            ok = m <= all;
                            need = m < all;
                        }
                    } else {
                        ok = 1;
                    }
                    if (ok && need)
                        locked_printf(stdout, "%s/%u\n", ip, m);
                    else if (ok)
                        locked_printf(stdout, "%s\n", ip);
                    else
                        VLOG(tid, "bad ip/subnet %s", dom);
                } else {
                    VLOG(tid, "wrong address family %s", ip);
                }
            } else if (dom_valid(dom)) {
                VLOG(tid, "resolving %s", dom);
                for (int i = 0; i < gr.eagain; i++) {
                    struct addrinfo *res;
                    int r = getaddrinfo(dom, NULL, &hints, &res);
                    if (r) {
                        VLOG(tid, "failed to resolve %s : result %d (%s)", dom, r, eai_str(r));
                        if (r == EAI_AGAIN) {
                            plat_sleep_ms((unsigned)gr.eagain_delay);
                            continue; /* a temporary failure */
                        }
                    } else {
                        print_ai(res);
                        freeaddrinfo(res);
                        ok = 1;
                    }
                    break;
                }
            } else if (gr.verbose) {
                char d2[sizeof(dom)];
                int i = 0;
                snprintf(d2, sizeof(d2), "%s", dom);
                for (; d2[i] && i < 64; i++)
                    if ((unsigned char)d2[i] < 0x20 || (d2[i] & 0x80))
                        d2[i] = '?';
                d2[i] = 0;
                VLOG(tid, "invalid domain : %s", d2);
            }
            locked_printf(ok ? gr.f_ok : gr.f_fail, "%s\n", dom);
        }
        stat_plus(ok);
    }
    VLOG(tid, "ended");
}

int xdns_answer_ips(const uint8_t *a, size_t len, sbuf *out)
{
    unsigned qd, an;
    char s[64];
    if (len < 12 || !(a[2] & 0x80))
        return -1;
    qd = (unsigned)a[4] << 8 | a[5];
    an = (unsigned)a[6] << 8 | a[7];
    a += 12;
    len -= 12;
    for (unsigned k = 0; k < qd; k++) {
        while (len && *a) {
            if ((size_t)*a + 1 > len)
                return -1;
            len -= (size_t)*a + 1;
            a += *a + 1;
        }
        if (len < 5)
            return -1;
        a += 5; /* the end of the name, type, class */
        len -= 5;
    }
    for (unsigned k = 0; k < an; k++) {
        size_t dlen;
        /* the name only as a pointer, as zapret2's */
        if (len < 12 || (*a & 0xC0) != 0xC0)
            return -1;
        dlen = (size_t)a[10] << 8 | a[11];
        if (len < dlen + 12)
            return -1;
        if (a[4] == 0 && a[5] == 1 && a[2] == 0) {
            if (a[3] == 1 && dlen == 4 && inet_ntop(AF_INET, a + 12, s, sizeof(s)))
                sb_printf(out, "%s\n", s);
            else if (a[3] == 28 && dlen == 16 && inet_ntop(AF_INET6, a + 12, s, sizeof(s)))
                sb_printf(out, "%s\n", s);
        }
        len -= 12 + dlen;
        a += 12 + dlen;
    }
    return 0;
}

static int make_query(const char *dom, int family)
{
    uint8_t q[300];
    uint64_t t = plat_now_ms() * 1000003u ^ plat_wall_ms();
    size_t l = strlen(dom);
    char name[256];
    /* one dot at the end is the root's */
    snprintf(name, sizeof(name), "%s", dom);
    if (l && l < sizeof(name) && name[l - 1] == '.')
        name[--l] = 0;
    /* an id hard to guess, as musl's */
    l = (l && name[l - 1] == '.') ? 0 : probe_dns_query(name, family == FAM6, (uint16_t)(t ^ t >> 16), q, sizeof(q));
    if (!l) {
        fprintf(stderr, "geneva resolve: could not make DNS query\n");
        return EXIT_USAGE;
    }
#ifdef _WIN32
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    if (fwrite(q, l, 1, stdout) != 1) {
        fprintf(stderr, "geneva resolve: could not write DNS query blob to stdout\n");
        return EXIT_IO;
    }
    return EXIT_OK;
}

static int parse_answer(void)
{
    sbuf in, out;
    int rc = EXIT_OK;
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
#endif
    sb_init(&in);
    sb_init(&out);
    if (read_all(stdin, &in) < 0 || !in.len) {
        fprintf(stderr, "geneva resolve: could not read DNS reply blob from stdin\n");
        rc = EXIT_IO;
    } else if (xdns_answer_ips((const uint8_t *)in.data, in.len < 8192 ? in.len : 8192, &out) < 0) {
        fprintf(stderr, "geneva resolve: could not parse DNS reply blob\n");
        rc = EXIT_FAIL;
    } else if (out.len) {
        fwrite(out.data, 1, out.len, stdout);
    }
    sb_free(&in);
    sb_free(&out);
    return rc;
}

int xcmd_resolve(int argc, char **argv)
{
    static const optdef defs[] = {
        {"ext", 0, 0, NULL, "turn on the extensions (required)"},
        {"family", 0, 1, "4|6|46", "addresses of IPv4, IPv6 or both (default 4)"},
        {"threads", 0, 1, "N", "resolver threads, 1-100 (default 1)"},
        {"eagain", 0, 1, "N", "tries on EAI_AGAIN, 1-1000 (default 10)"},
        {"eagain-delay", 0, 1, "MS", "pause between them, 0-100000 (default 500)"},
        {"verbose", 'v', 0, NULL, "the progress to stderr"},
        {"stats", 0, 1, "N", "counters to stderr every N names"},
        {"log-resolved", 0, 1, "FILE", "the names resolved"},
        {"log-failed", 0, 1, "FILE", "the names not resolved"},
        {"dns-make-query", 0, 1, "NAME", "print a DNS query for NAME (binary, A or with --family 6 AAAA) and exit"},
        {"dns-parse-query", 0, 0, NULL, "read a DNS answer (binary) from stdin, print its addresses and exit"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    int64_t v;
    const char *s;
    plat_thread_t *t;
    int n, started = 0, rc = EXIT_OK;
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva resolve: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva resolve --ext [options] < NAMES > ADDRESSES\n"
                  "Resolves a list of names (one per line) with the system resolver in\n"
                  "threads, as zapret2's mdig: the addresses of each, a line each; addresses\n"
                  "and subnets of the family in the list go out as they are.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (!arg_has(&a, "ext")) {
        fprintf(stderr, "geneva resolve: needs --ext\n");
        args_free(&a);
        return EXIT_USAGE;
    }
    memset(&gr, 0, sizeof(gr));
    gr.family = FAM4;
    s = arg_str(&a, "family", "4");
    if (!strcmp(s, "4"))
        gr.family = FAM4;
    else if (!strcmp(s, "6"))
        gr.family = FAM6;
    else if (!strcmp(s, "46"))
        gr.family = FAM4 | FAM6;
    else {
        fprintf(stderr, "geneva resolve: --family is 4, 6 or 46\n");
        args_free(&a);
        return EXIT_USAGE;
    }
    if (arg_int(&a, "threads", 1, 1, 100, &v) < 0)
        goto usage;
    n = (int)v;
    if (arg_int(&a, "eagain", EAGAIN_TRIES, 1, 1000, &v) < 0)
        goto usage;
    gr.eagain = (int)v;
    if (arg_int(&a, "eagain-delay", EAGAIN_DELAY, 0, 100000, &v) < 0)
        goto usage;
    gr.eagain_delay = (int)v;
    if (arg_int(&a, "stats", 0, 0, 1000000000, &v) < 0)
        goto usage;
    gr.stats_every = (int)v;
    gr.verbose = arg_has(&a, "verbose");
    if (arg_has(&a, "dns-parse-query")) {
        args_free(&a);
        return parse_answer();
    }
    if ((s = arg_str(&a, "dns-make-query", NULL))) {
        rc = make_query(s, gr.family);
        args_free(&a);
        return rc;
    }
    if ((s = arg_str(&a, "log-resolved", NULL)) && !(gr.f_ok = fopen(s, "w"))) {
        fprintf(stderr, "geneva resolve: failed to create %s\n", s);
        rc = EXIT_IO;
    }
    if (!rc && (s = arg_str(&a, "log-failed", NULL)) && !(gr.f_fail = fopen(s, "w"))) {
        fprintf(stderr, "geneva resolve: failed to create %s\n", s);
        rc = EXIT_IO;
    }
    args_free(&a);
    if (!rc) {
        plat_mutex_init(&gr.flock);
        plat_mutex_init(&gr.slock);
        gr.start = time(NULL);
        t = xmalloc(sizeof(*t) * (size_t)n);
        for (; started < n; started++)
            if (plat_thread_start(&t[started], resolver, (void *)(size_t)started) < 0) {
                fprintf(stderr, "geneva resolve: failed to create thread #%d\n", started);
                break;
            }
        for (int i = 0; i < started; i++)
            plat_thread_join(t[i]);
        free(t);
        stat_print(gr.stats_ct, gr.stats_ok);
        plat_mutex_destroy(&gr.slock);
        plat_mutex_destroy(&gr.flock);
        if (!started)
            rc = EXIT_FAIL;
    }
    if (gr.f_ok)
        fclose(gr.f_ok);
    if (gr.f_fail)
        fclose(gr.f_fail);
    return rc;
usage:
    args_free(&a);
    return EXIT_USAGE;
}
