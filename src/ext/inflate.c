/*
 * Inflate of the extensions: a DEFLATE decoder after Mark Adler's puff
 * (zlib's contrib/puff, the canonical-Huffman decoder of RFC 1951), with
 * an output that grows up to a limit, and the gzip and zlib wrappers
 * (ours). Altered from the original; puff's notice:
 *
 * Copyright (C) 2002-2013 Mark Adler, all rights reserved
 * version 2.3, 21 Jan 2013
 *
 * This software is provided 'as-is', without any express or implied
 * warranty.  In no event will the author be held liable for any damages
 * arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to the following restrictions:
 *
 * 1. The origin of this software must not be misrepresented; you must not
 *    claim that you wrote the original software. If you use this software
 *    in a product, an acknowledgment in the product documentation would be
 *    appreciated but is not required.
 * 2. Altered source versions must be plainly marked as such, and must not be
 *    misrepresented as being the original software.
 * 3. This notice may not be removed or altered from any source distribution.
 *
 * Mark Adler    madler@alumni.caltech.edu
 */
#include "inflate.h"

#include <stdlib.h>
#include <string.h>

#define MAXBITS 15
#define MAXLCODES 286
#define MAXDCODES 30
#define MAXCODES (MAXLCODES + MAXDCODES)
#define FIXLCODES 288

typedef struct {
    const uint8_t *in;
    size_t n, pos;
    uint32_t bitbuf;
    int bitcnt;
    uint8_t *out;
    size_t outlen, cap, max;
    int err; /* -1 bad or truncated, -2 over max */
} st_t;

typedef struct {
    short count[MAXBITS + 1];
    short symbol[FIXLCODES];
} huff;

static int bits(st_t *s, int need)
{
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->pos >= s->n) {
            s->err = -1;
            return 0;
        }
        val |= (uint32_t)s->in[s->pos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = val >> need;
    s->bitcnt -= need;
    return (int)(val & ((1u << need) - 1));
}

static int put(st_t *s, uint8_t c)
{
    if (s->outlen >= s->cap) {
        size_t nc;
        uint8_t *p;
        if (s->outlen >= s->max) {
            s->err = -2;
            return -1;
        }
        nc = s->cap ? s->cap * 2 : 4096;
        if (nc > s->max) nc = s->max;
        if (!(p = realloc(s->out, nc))) {
            s->err = -2;
            return -1;
        }
        s->out = p;
        s->cap = nc;
    }
    s->out[s->outlen++] = c;
    return 0;
}

static int stored(st_t *s)
{
    unsigned len;
    s->bitbuf = 0;
    s->bitcnt = 0;
    if (s->n - s->pos < 4) return s->err = -1;
    len = s->in[s->pos] | (unsigned)s->in[s->pos + 1] << 8;
    if ((s->in[s->pos + 2] ^ 0xff) != (len & 0xff) || (s->in[s->pos + 3] ^ 0xff) != (len >> 8)) return s->err = -1;
    s->pos += 4;
    if (s->n - s->pos < len) return s->err = -1;
    while (len--)
        if (put(s, s->in[s->pos++])) return s->err;
    return 0;
}

static int decode(st_t *s, const huff *h)
{
    int code = 0, first = 0, index = 0, len, count;
    for (len = 1; len <= MAXBITS; len++) {
        code |= bits(s, 1);
        if (s->err) return -1;
        count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    s->err = -1;
    return -1;
}

/* Returns 0 for a complete code, >0 for an incomplete one, <0 for an
 * over-subscribed one */
static int construct(huff *h, const short *length, int n)
{
    int sym, len, left;
    short offs[MAXBITS + 1];
    for (len = 0; len <= MAXBITS; len++) h->count[len] = 0;
    for (sym = 0; sym < n; sym++) h->count[length[sym]]++;
    if (h->count[0] == n) return 0;
    left = 1;
    for (len = 1; len <= MAXBITS; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0) return left;
    }
    offs[1] = 0;
    for (len = 1; len < MAXBITS; len++) offs[len + 1] = (short)(offs[len] + h->count[len]);
    for (sym = 0; sym < n; sym++)
        if (length[sym] != 0) h->symbol[offs[length[sym]]++] = (short)sym;
    return left;
}

static const short lbase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
                                35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const short lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
                               3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const short dbase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
                                193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
                                6145, 8193, 12289, 16385, 24577};
static const short dext[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
                               7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};

static int codes(st_t *s, const huff *lc, const huff *dc)
{
    int sym;
    unsigned len;
    size_t dist;
    do {
        sym = decode(s, lc);
        if (sym < 0) return -1;
        if (sym < 256) {
            if (put(s, (uint8_t)sym)) return -1;
        } else if (sym > 256) {
            sym -= 257;
            if (sym >= 29) return s->err = -1;
            len = (unsigned)(lbase[sym] + bits(s, lext[sym]));
            sym = decode(s, dc);
            if (sym < 0) return -1;
            if (sym >= 30) return s->err = -1;
            dist = (size_t)(dbase[sym] + bits(s, dext[sym]));
            if (s->err) return -1;
            if (dist > s->outlen) return s->err = -1;
            while (len--)
                if (put(s, s->out[s->outlen - dist])) return -1;
        }
    } while (sym != 256);
    return 0;
}

static int fixed(st_t *s)
{
    static huff lc, dc;
    static int built;
    if (!built) {
        short length[FIXLCODES];
        int sym;
        for (sym = 0; sym < 144; sym++) length[sym] = 8;
        for (; sym < 256; sym++) length[sym] = 9;
        for (; sym < 280; sym++) length[sym] = 7;
        for (; sym < FIXLCODES; sym++) length[sym] = 8;
        construct(&lc, length, FIXLCODES);
        for (sym = 0; sym < MAXDCODES; sym++) length[sym] = 5;
        construct(&dc, length, MAXDCODES);
        built = 1;
    }
    return codes(s, &lc, &dc);
}

static int dynamic(st_t *s)
{
    static const short order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
    int nlen, ndist, ncode, index, err;
    short lengths[MAXCODES];
    huff lc, dc;

    nlen = bits(s, 5) + 257;
    ndist = bits(s, 5) + 1;
    ncode = bits(s, 4) + 4;
    if (s->err) return -1;
    if (nlen > MAXLCODES || ndist > MAXDCODES) return s->err = -1;
    for (index = 0; index < ncode; index++) lengths[order[index]] = (short)bits(s, 3);
    for (; index < 19; index++) lengths[order[index]] = 0;
    if (s->err) return -1;
    if (construct(&lc, lengths, 19) != 0) return s->err = -1;

    index = 0;
    while (index < nlen + ndist) {
        int symbol, len;
        symbol = decode(s, &lc);
        if (symbol < 0) return -1;
        if (symbol < 16) {
            lengths[index++] = (short)symbol;
        } else {
            len = 0;
            if (symbol == 16) {
                if (index == 0) return s->err = -1;
                len = lengths[index - 1];
                symbol = 3 + bits(s, 2);
            } else if (symbol == 17) {
                symbol = 3 + bits(s, 3);
            } else {
                symbol = 11 + bits(s, 7);
            }
            if (s->err) return -1;
            if (index + symbol > nlen + ndist) return s->err = -1;
            while (symbol--) lengths[index++] = (short)len;
        }
    }
    if (lengths[256] == 0) return s->err = -1;
    err = construct(&lc, lengths, nlen);
    if (err < 0 || (err > 0 && nlen - lc.count[0] != 1)) return s->err = -1;
    err = construct(&dc, lengths + nlen, ndist);
    if (err < 0 || (err > 0 && ndist - dc.count[0] != 1)) return s->err = -1;
    return codes(s, &lc, &dc);
}

int xinf_raw(const uint8_t *in, size_t n, size_t max, uint8_t **out, size_t *outlen, size_t *used)
{
    st_t s;
    int last, type;
    memset(&s, 0, sizeof(s));
    s.in = in;
    s.n = n;
    s.max = max;
    *out = NULL;
    *outlen = 0;
    do {
        last = bits(&s, 1);
        type = bits(&s, 2);
        if (s.err) break;
        if (type == 0) stored(&s);
        else if (type == 1) fixed(&s);
        else if (type == 2) dynamic(&s);
        else s.err = -1;
    } while (!s.err && !last);
    if (s.err) {
        free(s.out);
        return s.err;
    }
    *out = s.out;
    *outlen = s.outlen;
    if (used) *used = s.pos; /* the bits left of the last byte are padding */
    return 0;
}

int xinf_is_gzip(const uint8_t *d, size_t n)
{
    return n >= 2 && d[0] == 0x1f && d[1] == 0x8b;
}

uint32_t xinf_crc32(uint32_t crc, const uint8_t *d, size_t n)
{
    static uint32_t tab[256];
    static int built;
    size_t i;
    if (!built) {
        uint32_t c, k;
        for (i = 0; i < 256; i++) {
            c = (uint32_t)i;
            for (k = 0; k < 8; k++) c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1;
            tab[i] = c;
        }
        built = 1;
    }
    crc = ~crc;
    for (i = 0; i < n; i++) crc = tab[(crc ^ d[i]) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static uint32_t adler32(const uint8_t *d, size_t n)
{
    uint32_t a = 1, b = 0;
    size_t i;
    for (i = 0; i < n; i++) {
        a = (a + d[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return b << 16 | a;
}

static uint32_t le32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int gzip_header(const uint8_t *in, size_t n, size_t *pos)
{
    size_t p = 10;
    uint8_t flg;
    if (n < 10 || in[2] != 8) return -1;
    flg = in[3];
    if (flg & 0xe0) return -1;
    if (flg & 4) { /* FEXTRA */
        size_t xl;
        if (n - p < 2) return -1;
        xl = in[p] | (size_t)in[p + 1] << 8;
        p += 2;
        if (n - p < xl) return -1;
        p += xl;
    }
    if (flg & 8) { /* FNAME */
        while (p < n && in[p]) p++;
        if (p++ >= n) return -1;
    }
    if (flg & 16) { /* FCOMMENT */
        while (p < n && in[p]) p++;
        if (p++ >= n) return -1;
    }
    if (flg & 2) { /* FHCRC */
        if (n - p < 2) return -1;
        if ((xinf_crc32(0, in, p) & 0xffff) != (uint32_t)(in[p] | in[p + 1] << 8)) return -1;
        p += 2;
    }
    *pos = p;
    return 0;
}

int xinf_unwrap(const uint8_t *in, size_t n, size_t max, uint8_t **out, size_t *outlen)
{
    size_t pos, used;
    int r;
    *out = NULL;
    *outlen = 0;
    if (xinf_is_gzip(in, n)) {
        if (gzip_header(in, n, &pos)) return -1;
        if ((r = xinf_raw(in + pos, n - pos, max, out, outlen, &used))) return r;
        pos += used;
        if (n - pos < 8 || le32(in + pos) != xinf_crc32(0, *out, *outlen) ||
            le32(in + pos + 4) != (uint32_t)*outlen)
            goto bad;
        return 0;
    }
    /* zlib: CMF FLG, deflate with a window of at most 32K, no dictionary */
    if (n < 2 || (in[0] & 0x0f) != 8 || (in[0] >> 4) > 7 || ((in[0] << 8 | in[1]) % 31) || (in[1] & 0x20)) return -1;
    if ((r = xinf_raw(in + 2, n - 2, max, out, outlen, &used))) return r;
    pos = 2 + used;
    if (n - pos < 4 ||
        ((uint32_t)in[pos] << 24 | (uint32_t)in[pos + 1] << 16 | (uint32_t)in[pos + 2] << 8 | in[pos + 3]) != adler32(*out, *outlen))
        goto bad;
    return 0;
bad:
    free(*out);
    *out = NULL;
    *outlen = 0;
    return -1;
}
