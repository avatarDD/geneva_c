#include "blob.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext.h"
#include "quic.h"

typedef struct {
    char name[BLOB_NAME_MAX];
    xblob b;
    uint8_t *own;
} blob_item;

static blob_item *g_blobs;
static size_t g_n;

int blob_name_ok(const char *s)
{
    if (!*s || !(*s == '_' || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z')))
        return 0;
    for (; *s; s++)
        if (!(*s == '_' || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9')))
            return 0;
    return 1;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int blob_hex(const char *s, size_t max, uint8_t **out, size_t *len)
{
    size_t n;
    uint8_t *b;
    *out = NULL;
    *len = 0;
    if (s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
        return -1;
    s += 2;
    n = strlen(s);
    if (n % 2 || n / 2 > max)
        return -1;
    b = xmalloc(n / 2 + 1);
    for (size_t i = 0; i < n / 2; i++) {
        int h = hexval(s[2 * i]), l = hexval(s[2 * i + 1]);
        if (h < 0 || l < 0) {
            free(b);
            return -1;
        }
        b[i] = (uint8_t)(h << 4 | l);
    }
    *out = b;
    *len = n / 2;
    return 0;
}

const xblob *blob_find(const char *name)
{
    for (size_t i = 0; i < g_n; i++)
        if (!strcmp(g_blobs[i].name, name))
            return &g_blobs[i].b;
    return NULL;
}

/* Takes data (malloc'ed); -1 when the name is taken */
static int add(const char *name, uint8_t *data, size_t len)
{
    blob_item *it;
    if (blob_find(name)) {
        free(data);
        return -1;
    }
    g_blobs = xrealloc(g_blobs, (g_n + 1) * sizeof(*g_blobs));
    it = &g_blobs[g_n++];
    memset(it, 0, sizeof(*it));
    snprintf(it->name, sizeof(it->name), "%s", name);
    it->own = data;
    it->b.data = data;
    it->b.len = len;
    return 0;
}

void blob_free_all(void)
{
    for (size_t i = 0; i < g_n; i++)
        free(g_blobs[i].own);
    free(g_blobs);
    g_blobs = NULL;
    g_n = 0;
}

static int load_file(const char *fn, unsigned long long ofs, uint8_t **out, size_t *len, sbuf *err)
{
    FILE *f = fopen(fn, "rb");
    uint8_t *b;
    size_t n;
    long sz;
    *out = NULL;
    if (!f) {
        sb_printf(err, "cannot read \"%s\"", fn);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) < 0 || (sz = ftell(f)) < 0) {
        fclose(f);
        sb_printf(err, "cannot read \"%s\"", fn);
        return -1;
    }
    if (sz && ofs >= (unsigned long long)sz) {
        fclose(f);
        sb_printf(err, "offset %llu is beyond the size of \"%s\" (%ld)", ofs, fn, sz);
        return -1;
    }
    if ((unsigned long long)sz - ofs > BLOB_FILE_MAX) {
        fclose(f);
        sb_printf(err, "\"%s\" is longer than %d bytes", fn, BLOB_FILE_MAX);
        return -1;
    }
    n = (size_t)((unsigned long long)sz - ofs);
    b = xmalloc(n + 1);
    if (fseek(f, (long)ofs, SEEK_SET) < 0 || fread(b, 1, n, f) != n) {
        fclose(f);
        free(b);
        sb_printf(err, "cannot read \"%s\"", fn);
        return -1;
    }
    fclose(f);
    *out = b;
    *len = n;
    return 0;
}

int blob_opt(const char *spec, sbuf *err)
{
    const char *colon = strchr(spec, ':'), *v;
    char name[BLOB_NAME_MAX];
    uint8_t *data;
    size_t len;
    if (!colon || (size_t)(colon - spec) >= sizeof(name)) {
        sb_printf(err, "\"%s\" is not NAME:0xHEX or NAME:[+OFS]@FILE", spec);
        return -1;
    }
    memcpy(name, spec, (size_t)(colon - spec));
    name[colon - spec] = 0;
    if (!blob_name_ok(name)) {
        sb_printf(err, "bad blob name \"%s\" (a letter or _, then letters, digits, _)", name);
        return -1;
    }
    if (blob_find(name)) {
        sb_printf(err, "duplicate blob name \"%s\"", name);
        return -1;
    }
    v = colon + 1;
    if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
        if (blob_hex(v, BLOB_HEX_MAX, &data, &len) < 0 || !len) {
            sb_printf(err, "bad hex string in blob \"%s\"", name);
            return -1;
        }
    } else {
        unsigned long long ofs = 0;
        if (*v == '+') {
            char *e;
            ofs = strtoull(v + 1, &e, 10);
            if (e == v + 1 || *e != '@') {
                sb_printf(err, "bad offset in blob \"%s\" (+OFS@FILE)", name);
                return -1;
            }
            v = e;
        }
        if (*v == '@')
            v++;
        if (!*v) {
            sb_printf(err, "no file for blob \"%s\"", name);
            return -1;
        }
        if (load_file(v, ofs, &data, &len, err) < 0)
            return -1;
    }
    add(name, data, len);
    return 0;
}

/* ---- generators ------------------------------------------------------------ */

static uint32_t xs(uint32_t *s)
{
    *s ^= *s << 13;
    *s ^= *s >> 17;
    *s ^= *s << 5;
    return *s;
}

static void fill(uint8_t *p, size_t n, uint32_t *s)
{
    for (size_t i = 0; i < n; i++)
        p[i] = (uint8_t)xs(s);
}

static void put16(uint8_t *p, size_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

/* A ClientHello handshake message at out (quic: TLS 1.3 only, ALPN h3 and
 * transport parameters). Returns the length, 0 when cap is too small. */
static size_t client_hello(const char *sni, int quic, uint32_t *rs, uint8_t *out, size_t cap)
{
    static const uint8_t suites13[] = {0x13, 0x01, 0x13, 0x02, 0x13, 0x03};
    static const uint8_t suites12[] = {0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30, 0xcc, 0xa9,
                                       0xcc, 0xa8, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d};
    static const uint8_t common[] = {
        0x00, 0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, /* supported_groups */
        0x00, 0x0d, 0x00, 0x12, 0x00, 0x10, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, /* signature_algorithms */
        0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01,
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, /* psk_key_exchange_modes */
    };
    static const uint8_t tcp_only[] = {
        0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, /* ec_point_formats */
        0x00, 0x23, 0x00, 0x00,             /* session_ticket */
        0x00, 0x17, 0x00, 0x00,             /* extended_master_secret */
        0xff, 0x01, 0x00, 0x01, 0x00,       /* renegotiation_info */
        0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1', /* ALPN */
        0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, /* supported_versions 1.3, 1.2 */
    };
    static const uint8_t quic_only[] = {
        0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '3', /* ALPN */
        0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,           /* supported_versions 1.3 */
        /* quic_transport_parameters: initial_max_data 1 MB, streams, idle timeout 30 s */
        0x00, 0x39, 0x00, 0x13, 0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x09, 0x02,
        0x40, 0x64, 0x01, 0x04, 0x80, 0x00, 0x75, 0x30,
    };
    size_t sl = strlen(sni), n = 0, ext;
    if (sl > 253 || cap < 512 + sl)
        return 0;
    out[n++] = 0x01;
    n += 3;
    out[n++] = 0x03;
    out[n++] = 0x03;
    fill(out + n, 32, rs);
    n += 32;
    if (quic) {
        out[n++] = 0; /* no legacy session id in QUIC */
    } else {
        out[n++] = 32;
        fill(out + n, 32, rs);
        n += 32;
    }
    put16(out + n, sizeof(suites13) + (quic ? 0 : sizeof(suites12)));
    n += 2;
    memcpy(out + n, suites13, sizeof(suites13));
    n += sizeof(suites13);
    if (!quic) {
        memcpy(out + n, suites12, sizeof(suites12));
        n += sizeof(suites12);
    }
    out[n++] = 1;
    out[n++] = 0;
    ext = n;
    n += 2;
    put16(out + n, 0x0000);
    put16(out + n + 2, sl + 5);
    put16(out + n + 4, sl + 3);
    out[n + 6] = 0;
    put16(out + n + 7, sl);
    memcpy(out + n + 9, sni, sl);
    n += 9 + sl;
    memcpy(out + n, common, sizeof(common));
    n += sizeof(common);
    if (quic) {
        memcpy(out + n, quic_only, sizeof(quic_only));
        n += sizeof(quic_only);
    } else {
        memcpy(out + n, tcp_only, sizeof(tcp_only));
        n += sizeof(tcp_only);
    }
    /* key_share: x25519, any 32 bytes make a public key */
    put16(out + n, 0x0033);
    put16(out + n + 2, 38);
    put16(out + n + 4, 36);
    put16(out + n + 6, 0x001d);
    put16(out + n + 8, 32);
    fill(out + n + 10, 32, rs);
    n += 42;
    put16(out + ext, n - ext - 2);
    out[1] = 0;
    put16(out + 2, n - 4);
    return n;
}

size_t blob_make_tls(const char *sni, size_t total, uint32_t seed, uint8_t *out, size_t cap)
{
    uint32_t rs = seed ? seed : 1;
    size_t n, hs, ext_off;
    if (cap < 9)
        return 0;
    hs = client_hello(sni, 0, &rs, out + 5, cap - 5);
    if (!hs)
        return 0;
    n = 5 + hs;
    if (total) {
        /* a padding extension up to the size (RFC 7685), last */
        size_t pad;
        if (total < n + 4 || total > cap || total - 5 > 0xffff)
            return 0;
        pad = total - n - 4;
        put16(out + n, 0x0015);
        put16(out + n + 2, pad);
        memset(out + n + 4, 0, pad);
        n = total;
        /* the extensions length after session id, suites, compression */
        ext_off = 5 + 4 + 2 + 32 + 1 + 32;
        ext_off += 2 + ((size_t)out[ext_off] << 8 | out[ext_off + 1]);
        ext_off += 1 + out[ext_off];
        put16(out + ext_off, n - ext_off - 2);
        out[6] = (uint8_t)((n - 9) >> 16);
        put16(out + 7, n - 9);
    }
    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x01;
    put16(out + 3, n - 5);
    return n;
}

size_t blob_make_quic(const char *sni, uint32_t seed, uint8_t *out, size_t cap)
{
    uint8_t frames[1200], dcid[8], scid[8];
    uint32_t rs = seed ? seed : 1;
    size_t hs;
    fill(dcid, 8, &rs);
    fill(scid, 8, &rs);
    /* one CRYPTO frame at offset 0 with a 2-byte length */
    hs = client_hello(sni, 1, &rs, frames + 4, sizeof(frames) - 4);
    if (!hs || hs > 0x3fff)
        return 0;
    frames[0] = 0x06;
    frames[1] = 0x00;
    frames[2] = (uint8_t)(0x40 | hs >> 8);
    frames[3] = (uint8_t)hs;
    return quic_initial_build(QUIC_V1, dcid, 8, scid, 8, 0, frames, hs + 4, 1200, out, cap);
}

static const char fake_http[] = "GET / HTTP/1.1\r\n"
                                "Host: www.iana.org\r\n"
                                "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0\r\n"
                                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                                "Accept-Language: en-US,en;q=0.5\r\n"
                                "Accept-Encoding: gzip, deflate\r\n"
                                "Connection: keep-alive\r\n"
                                "\r\n";

void blob_reset(void)
{
    uint8_t *b;
    size_t n;
    blob_free_all();
    b = xmalloc(680);
    n = blob_make_tls("www.iana.org", 680, 0x9e3779b9u, b, 680);
    add("fake_default_tls", b, n);
    b = xmalloc(sizeof(fake_http));
    memcpy(b, fake_http, sizeof(fake_http) - 1);
    add("fake_default_http", b, sizeof(fake_http) - 1);
    b = xcalloc(1, 620);
    b[0] = 0x40;
    add("fake_default_quic", b, 620);
#if GENEVA_EXT_CRYPTO
    b = xmalloc(1200);
    n = blob_make_quic("www.iana.org", 0x7f4a7c15u, b, 1200);
    if (n)
        add("fake_quic_initial", b, n);
    else
        free(b);
#endif
}
