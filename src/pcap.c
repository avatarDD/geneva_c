/* pcap / pcapng reading and pcap writing. See pcap.h. */
#include "pcap.h"

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <fcntl.h>
#  include <io.h>
#endif

#define PCAP_MAGIC_US 0xa1b2c3d4u
#define PCAP_MAGIC_NS 0xa1b23c4du
#define PCAPNG_SHB 0x0a0d0d0au
#define PCAPNG_BOM 0x1a2b3c4du
#define MAX_SNAP (256u * 1024)
#define MAX_BLOCK (16u * 1024 * 1024)
#define MAX_IFACES 64

struct pcap_reader {
    FILE *f;
    int ng;        /* pcapng */
    int swap;      /* file byte order differs from ours */
    int nsec;      /* classic pcap: nanosecond stamps */
    int linktype;  /* classic pcap */
    struct {
        int linktype;
        uint64_t ts_div; /* ticks per second */
    } ifs[MAX_IFACES];
    int nifs;
    uint8_t *buf;
    size_t cap;
};

struct pcap_writer {
    FILE *f;
    int failed;
};

static uint32_t bswap32(uint32_t v)
{
    return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24);
}

static uint16_t bswap16(uint16_t v) { return (uint16_t)((v >> 8) | (v << 8)); }

static uint32_t rd32(const pcap_reader *r, const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return r->swap ? bswap32(v) : v;
}

static uint16_t rd16(const pcap_reader *r, const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return r->swap ? bswap16(v) : v;
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static int read_exact(FILE *f, void *buf, size_t n)
{
    return fread(buf, 1, n, f) == n ? 0 : -1;
}

static void reserve(pcap_reader *r, size_t n)
{
    if (n > r->cap) {
        r->buf = xrealloc(r->buf, n);
        r->cap = n;
    }
}

/* ---- opening ------------------------------------------------------------- */

static FILE *open_path(const char *path, const char *mode, sbuf *err)
{
    FILE *f;
    if (!strcmp(path, "-")) {
        f = mode[0] == 'r' ? stdin : stdout;
#ifdef _WIN32
        _setmode(_fileno(f), _O_BINARY);
#endif
        return f;
    }
    f = fopen(path, mode);
    if (!f)
        sb_printf(err, "cannot open %s", path);
    return f;
}

pcap_reader *pcap_open_read(const char *path, sbuf *err)
{
    FILE *f = open_path(path, "rb", err);
    return f ? pcap_read_fp(f, err) : NULL;
}

pcap_reader *pcap_read_fp(FILE *f, sbuf *err)
{
    uint8_t h[24];
    uint32_t magic;
    pcap_reader *r = xcalloc(1, sizeof(*r));
    r->f = f;
    if (read_exact(f, h, 4) < 0) {
        sb_puts(err, "empty or truncated capture file");
        goto fail;
    }
    memcpy(&magic, h, 4);
    if (magic == PCAPNG_SHB) {
        r->ng = 1;
        /* The SHB is read like any other block by pcap_next(); push the
         * type back by re-reading it there. */
        if (read_exact(f, h + 4, 8) < 0) {
            sb_puts(err, "truncated pcapng header");
            goto fail;
        }
        memcpy(&magic, h + 8, 4);
        if (magic == PCAPNG_BOM)
            r->swap = 0;
        else if (bswap32(magic) == PCAPNG_BOM)
            r->swap = 1;
        else {
            sb_puts(err, "bad pcapng byte-order magic");
            goto fail;
        }
        {
            uint32_t blen = rd32(r, h + 4);
            if (blen < 28 || blen > MAX_BLOCK || blen % 4) {
                sb_puts(err, "bad pcapng section header");
                goto fail;
            }
            reserve(r, blen);
            if (read_exact(f, r->buf, blen - 12) < 0) {
                sb_puts(err, "truncated pcapng section header");
                goto fail;
            }
        }
        return r;
    }
    if (magic == PCAP_MAGIC_US || magic == PCAP_MAGIC_NS) {
        r->swap = 0;
    } else if (bswap32(magic) == PCAP_MAGIC_US || bswap32(magic) == PCAP_MAGIC_NS) {
        r->swap = 1;
        magic = bswap32(magic);
    } else {
        sb_puts(err, "not a pcap or pcapng file");
        goto fail;
    }
    r->nsec = magic == PCAP_MAGIC_NS;
    if (read_exact(f, h + 4, 20) < 0) {
        sb_puts(err, "truncated pcap header");
        goto fail;
    }
    r->linktype = (int)(rd32(r, h + 20) & 0x0fffffff);
    return r;
fail:
    pcap_close_read(r);
    return NULL;
}

void pcap_close_read(pcap_reader *r)
{
    if (!r)
        return;
    if (r->f && r->f != stdin)
        fclose(r->f);
    free(r->buf);
    free(r);
}

/* ---- link layers --------------------------------------------------------- */

static int is_ip(const uint8_t *p, size_t n)
{
    return n >= 1 && ((p[0] >> 4) == 4 || (p[0] >> 4) == 6);
}

/* Removes link headers and trailing padding; sets rec->ip/ip_len. */
static void strip_link(pcap_rec *rec, const uint8_t *d, size_t n)
{
    size_t off = 0, iplen;
    int ok = 0;
    rec->ip = NULL;
    rec->ip_len = 0;
    switch (rec->linktype) {
    case LINKTYPE_RAW:
    case LINKTYPE_IPV4:
    case LINKTYPE_IPV6:
    case 12: /* LINKTYPE_RAW on some BSDs */
        ok = 1;
        break;
    case LINKTYPE_ETHERNET: {
        uint16_t et;
        if (n < 14)
            return;
        et = be16(d + 12);
        off = 14;
        while ((et == 0x8100 || et == 0x88a8 || et == 0x9100) && off + 4 <= n) {
            et = be16(d + off + 2);
            off += 4;
        }
        ok = et == 0x0800 || et == 0x86dd;
        break;
    }
    case LINKTYPE_LINUX_SLL:
        if (n < 16)
            return;
        off = 16;
        ok = be16(d + 14) == 0x0800 || be16(d + 14) == 0x86dd;
        break;
    case LINKTYPE_LINUX_SLL2:
        if (n < 20)
            return;
        off = 20;
        ok = be16(d) == 0x0800 || be16(d) == 0x86dd;
        break;
    case LINKTYPE_NULL:
        /* 4-byte address family in the capturing host's byte order */
        if (n < 4)
            return;
        off = 4;
        ok = 1;
        break;
    default:
        return;
    }
    if (!ok || off >= n || !is_ip(d + off, n - off))
        return;
    d += off;
    n -= off;
    /* drop Ethernet padding beyond the IP datagram */
    if ((d[0] >> 4) == 4 && n >= 20) {
        iplen = be16(d + 2);
        if (iplen >= 20 && iplen < n)
            n = iplen;
    } else if ((d[0] >> 4) == 6 && n >= 40) {
        iplen = 40 + (size_t)be16(d + 4);
        if (be16(d + 4) && iplen < n)
            n = iplen;
    }
    rec->ip = d;
    rec->ip_len = n;
}

/* ---- reading ------------------------------------------------------------- */

static int next_classic(pcap_reader *r, pcap_rec *rec, sbuf *err)
{
    uint8_t h[16];
    size_t got = fread(h, 1, sizeof(h), r->f);
    uint32_t sec, frac, incl;
    if (got == 0)
        return 0;
    if (got != sizeof(h)) {
        sb_puts(err, "truncated pcap record header");
        return -1;
    }
    sec = rd32(r, h);
    frac = rd32(r, h + 4);
    incl = rd32(r, h + 8);
    if (incl > MAX_SNAP) {
        sb_printf(err, "pcap record of %u bytes is too large", incl);
        return -1;
    }
    reserve(r, incl ? incl : 1);
    if (read_exact(r->f, r->buf, incl) < 0) {
        sb_puts(err, "truncated pcap record");
        return -1;
    }
    rec->ts_ns = (uint64_t)sec * 1000000000u + (uint64_t)frac * (r->nsec ? 1 : 1000);
    rec->caplen = incl;
    rec->origlen = rd32(r, h + 12);
    rec->linktype = r->linktype;
    strip_link(rec, r->buf, incl);
    return 1;
}

static uint64_t ts_div_from_option(uint8_t v)
{
    uint64_t d = 1;
    if (v & 0x80) {
        for (int i = 0; i < (v & 0x7f) && i < 63; i++)
            d *= 2;
    } else {
        for (int i = 0; i < v && i < 19; i++)
            d *= 10;
    }
    return d ? d : 1;
}

static void parse_idb(pcap_reader *r, const uint8_t *b, size_t blen)
{
    int idx = r->nifs;
    const uint8_t *o = b + 16, *end = b + blen - 4;
    if (r->nifs >= MAX_IFACES)
        return;
    r->ifs[idx].linktype = rd16(r, b + 8);
    r->ifs[idx].ts_div = 1000000;
    while (o + 4 <= end) {
        uint16_t code = rd16(r, o), len = rd16(r, o + 2);
        if (code == 0 || o + 4 + len > end)
            break;
        if (code == 9 && len >= 1) /* if_tsresol */
            r->ifs[idx].ts_div = ts_div_from_option(o[4]);
        o += 4 + ((len + 3u) & ~3u);
    }
    r->nifs++;
}

static uint64_t ticks_to_ns(uint64_t ticks, uint64_t div)
{
    if (div == 1000000000u)
        return ticks;
    return ticks / div * 1000000000u + ticks % div * 1000000000u / div;
}

static int next_ng(pcap_reader *r, pcap_rec *rec, sbuf *err)
{
    for (;;) {
        uint8_t h[8];
        size_t got = fread(h, 1, sizeof(h), r->f);
        uint32_t type, blen;
        const uint8_t *b;
        if (got == 0)
            return 0;
        if (got != sizeof(h)) {
            sb_puts(err, "truncated pcapng block");
            return -1;
        }
        memcpy(&type, h, 4);
        if (type == PCAPNG_SHB) {
            /* a new section: byte order and interfaces start over */
            uint8_t bom[4];
            uint32_t m;
            if (read_exact(r->f, bom, 4) < 0)
                return -1;
            memcpy(&m, bom, 4);
            r->swap = m != PCAPNG_BOM;
            r->nifs = 0;
            blen = rd32(r, h + 4);
            if (blen < 28 || blen > MAX_BLOCK || blen % 4) {
                sb_puts(err, "bad pcapng section header");
                return -1;
            }
            reserve(r, blen);
            if (read_exact(r->f, r->buf, blen - 12) < 0)
                return -1;
            continue;
        }
        type = rd32(r, h);
        blen = rd32(r, h + 4);
        if (blen < 12 || blen > MAX_BLOCK || blen % 4) {
            sb_printf(err, "bad pcapng block length %u", blen);
            return -1;
        }
        reserve(r, blen);
        memcpy(r->buf, h, 8);
        if (read_exact(r->f, r->buf + 8, blen - 8) < 0) {
            sb_puts(err, "truncated pcapng block");
            return -1;
        }
        b = r->buf;
        if (type == 1 && blen >= 20) { /* IDB */
            parse_idb(r, b, blen);
        } else if ((type == 6 || type == 2) && blen >= 32) { /* EPB, obsolete PB */
            uint32_t ifc = type == 6 ? rd32(r, b + 8) : rd16(r, b + 8);
            uint64_t ts = ((uint64_t)rd32(r, b + 12) << 32) | rd32(r, b + 16);
            uint32_t cap = rd32(r, b + 20);
            if (cap > blen - 32) {
                sb_puts(err, "pcapng packet overruns its block");
                return -1;
            }
            if (ifc >= (uint32_t)r->nifs) {
                sb_puts(err, "pcapng packet for an undeclared interface");
                return -1;
            }
            rec->ts_ns = ticks_to_ns(ts, r->ifs[ifc].ts_div);
            rec->caplen = cap;
            rec->origlen = rd32(r, b + 24);
            rec->linktype = r->ifs[ifc].linktype;
            strip_link(rec, b + 28, cap);
            return 1;
        } else if (type == 3 && blen >= 16) { /* SPB */
            uint32_t orig = rd32(r, b + 8);
            size_t cap = MIN((size_t)orig, (size_t)blen - 16);
            if (r->nifs < 1) {
                sb_puts(err, "pcapng packet before any interface");
                return -1;
            }
            rec->ts_ns = 0;
            rec->caplen = cap;
            rec->origlen = orig;
            rec->linktype = r->ifs[0].linktype;
            strip_link(rec, b + 12, cap);
            return 1;
        }
        /* other blocks (name resolution, statistics, custom) are skipped */
    }
}

int pcap_next(pcap_reader *r, pcap_rec *rec, sbuf *err)
{
    memset(rec, 0, sizeof(*rec));
    return r->ng ? next_ng(r, rec, err) : next_classic(r, rec, err);
}

/* ---- writing ------------------------------------------------------------- */

static void put32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

pcap_writer *pcap_open_write(const char *path, sbuf *err)
{
    FILE *f = open_path(path, "wb", err);
    return f ? pcap_write_fp(f, err) : NULL;
}

pcap_writer *pcap_write_fp(FILE *f, sbuf *err)
{
    uint8_t h[24] = {0};
    pcap_writer *w = xcalloc(1, sizeof(*w));
    w->f = f;
    put32le(h, PCAP_MAGIC_NS);
    h[4] = 2; /* version 2.4 */
    h[6] = 4;
    put32le(h + 16, 65535);
    put32le(h + 20, LINKTYPE_RAW);
    if (fwrite(h, 1, sizeof(h), f) != sizeof(h)) {
        sb_puts(err, "cannot write pcap header");
        w->failed = 1;
    }
    return w;
}

int pcap_write(pcap_writer *w, uint64_t ts_ns, const uint8_t *ip, size_t len)
{
    uint8_t h[16];
    put32le(h, (uint32_t)(ts_ns / 1000000000u));
    put32le(h + 4, (uint32_t)(ts_ns % 1000000000u));
    put32le(h + 8, (uint32_t)len);
    put32le(h + 12, (uint32_t)len);
    if (fwrite(h, 1, sizeof(h), w->f) != sizeof(h) || fwrite(ip, 1, len, w->f) != len) {
        w->failed = 1;
        return -1;
    }
    return 0;
}

int pcap_close_write(pcap_writer *w)
{
    int rc;
    if (!w)
        return 0;
    if (fflush(w->f) != 0)
        w->failed = 1;
    if (w->f != stdout && fclose(w->f) != 0)
        w->failed = 1;
    rc = w->failed ? -1 : 0;
    free(w);
    return rc;
}
