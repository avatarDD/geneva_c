#include "quic.h"

#include <string.h>

#include "ext.h"
#if GENEVA_EXT_CRYPTO
#  include "crypto.h"
#endif

static const uint8_t salt_v1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
static const uint8_t salt_v2[20] = {0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                                    0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9};
static const uint8_t salt_d29[20] = {0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
                                     0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99};

typedef struct {
    const uint8_t *salt;
    const char *key, *iv, *hp;
    uint8_t initial_type; /* long header packet type bits of an Initial */
} vparams;

static int params(uint32_t v, vparams *vp)
{
    if (v == QUIC_V1 || (v >= 0xff00001du && v <= 0xff000020u)) {
        vp->salt = v == QUIC_V1 ? salt_v1 : salt_d29;
        vp->key = "quic key", vp->iv = "quic iv", vp->hp = "quic hp";
        vp->initial_type = 0;
        return 0;
    }
    if (v == QUIC_V2) {
        vp->salt = salt_v2;
        vp->key = "quicv2 key", vp->iv = "quicv2 iv", vp->hp = "quicv2 hp";
        vp->initial_type = 1;
        return 0;
    }
    return -1;
}

int quic_varint(const uint8_t *p, size_t n, size_t *off, uint64_t *v)
{
    size_t len;
    if (*off >= n)
        return -1;
    len = (size_t)1 << (p[*off] >> 6);
    if (len > n - *off)
        return -1;
    *v = p[*off] & 0x3f;
    for (size_t i = 1; i < len; i++)
        *v = *v << 8 | p[*off + i];
    *off += len;
    return 0;
}

int quic_is_initial(const uint8_t *p, size_t n, quic_initial *h)
{
    size_t off;
    uint64_t tok, plen;
    vparams vp;
    memset(h, 0, sizeof(*h));
    if (n < 7 || (p[0] & 0xc0) != 0xc0) /* long header, fixed bit */
        return 0;
    h->version = (uint32_t)p[1] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 8 | p[4];
    if (params(h->version, &vp) < 0 || ((p[0] >> 4) & 3) != vp.initial_type)
        return 0;
    off = 5;
    h->dcid_len = p[off++];
    if (h->dcid_len > 20 || off + h->dcid_len + 1 > n)
        return 0;
    memcpy(h->dcid, p + off, h->dcid_len);
    off += h->dcid_len;
    h->scid_len = p[off++];
    if (h->scid_len > 20 || off + h->scid_len > n)
        return 0;
    memcpy(h->scid, p + off, h->scid_len);
    off += h->scid_len;
    if (quic_varint(p, n, &off, &tok) < 0 || tok > n - off)
        return 0;
    off += (size_t)tok;
    if (quic_varint(p, n, &off, &plen) < 0 || plen > n - off || plen < 4 + 16)
        return 0;
    h->pn_off = off;
    h->pkt_len = off + (size_t)plen;
    return 1;
}

#if !GENEVA_EXT_CRYPTO
long quic_initial_decrypt(const uint8_t *p, size_t n, quic_initial *h, uint8_t *out, size_t cap)
{
    (void)p, (void)n, (void)h, (void)out, (void)cap;
    return -1;
}
#else
long quic_initial_decrypt(const uint8_t *p, size_t n, quic_initial *h, uint8_t *out, size_t cap)
{
    vparams vp;
    uint8_t initial[32], client[32], key[16], iv[12], hp[16], mask[16], hdr[512];
    uint8_t nonce[12];
    aes_ctx hpc;
    gcm_ctx g;
    size_t pnl, hlen, clen;
    long rc = -1;

    if (!quic_is_initial(p, n, h) || params(h->version, &vp) < 0)
        return -1;
    if (h->pn_off + 4 + 16 > h->pkt_len || h->pn_off + 4 > sizeof(hdr)) /* a long token */
        return -1;
    hkdf_extract(vp.salt, 20, h->dcid, h->dcid_len, initial);
    if (hkdf_expand_label(initial, "client in", NULL, 0, client, 32) < 0 ||
        hkdf_expand_label(client, vp.key, NULL, 0, key, 16) < 0 ||
        hkdf_expand_label(client, vp.iv, NULL, 0, iv, 12) < 0 ||
        hkdf_expand_label(client, vp.hp, NULL, 0, hp, 16) < 0)
        goto out;
    /* header protection: the sample starts 4 bytes after the packet number */
    aes_init(&hpc, hp, 16);
    aes_encrypt_block(&hpc, p + h->pn_off + 4, mask);
    memcpy(hdr, p, h->pn_off);
    hdr[0] ^= mask[0] & 0x0f;
    pnl = (size_t)(hdr[0] & 3) + 1;
    h->pn = 0;
    for (size_t i = 0; i < pnl; i++) {
        hdr[h->pn_off + i] = p[h->pn_off + i] ^ mask[1 + i];
        h->pn = h->pn << 8 | hdr[h->pn_off + i];
    }
    hlen = h->pn_off + pnl;
    if (hlen + 16 > h->pkt_len)
        goto out;
    clen = h->pkt_len - hlen - 16;
    if (clen > cap)
        goto out;
    memcpy(nonce, iv, 12);
    for (size_t i = 0; i < 8; i++)
        nonce[11 - i] ^= (uint8_t)(h->pn >> (8 * i));
    gcm_init(&g, key, 16);
    if (gcm_decrypt(&g, nonce, hdr, hlen, p + hlen, out, clen, p + hlen + clen) == 0)
        rc = (long)clen;
out:
    secure_zero(initial, sizeof(initial));
    secure_zero(client, sizeof(client));
    secure_zero(key, sizeof(key));
    secure_zero(iv, sizeof(iv));
    secure_zero(hp, sizeof(hp));
    secure_zero(&g, sizeof(g));
    secure_zero(&hpc, sizeof(hpc));
    return rc;
}
#endif

int quic_crypto_stream(const uint8_t *f, size_t n, uint8_t *out, size_t cap, size_t *len)
{
    size_t off = 0;
    /* a small map of what is filled, enough for the Initial-sized streams */
    uint8_t have[2048];
    size_t top = 0;
    memset(have, 0, sizeof(have));
    *len = 0;
    if (cap > sizeof(have) * 8)
        cap = sizeof(have) * 8;
    while (off < n) {
        uint64_t type, a, b, c;
        if (quic_varint(f, n, &off, &type) < 0)
            return -1;
        switch (type) {
        case 0x00: /* PADDING */
        case 0x01: /* PING */
            break;
        case 0x02:
        case 0x03: { /* ACK: largest, delay, range count, first range, ranges [, ECN] */
            uint64_t ranges;
            if (quic_varint(f, n, &off, &a) < 0 || quic_varint(f, n, &off, &b) < 0 ||
                quic_varint(f, n, &off, &ranges) < 0 || quic_varint(f, n, &off, &c) < 0)
                return -1;
            for (uint64_t i = 0; i < ranges; i++)
                if (quic_varint(f, n, &off, &a) < 0 || quic_varint(f, n, &off, &b) < 0)
                    return -1;
            if (type == 0x03)
                for (int i = 0; i < 3; i++)
                    if (quic_varint(f, n, &off, &a) < 0)
                        return -1;
            break;
        }
        case 0x06: { /* CRYPTO: offset, length, data */
            if (quic_varint(f, n, &off, &a) < 0 || quic_varint(f, n, &off, &b) < 0 || b > n - off)
                return -1;
            for (uint64_t i = 0; i < b; i++) {
                uint64_t pos = a + i;
                if (pos >= cap)
                    break;
                out[pos] = f[off + i];
                have[pos >> 3] |= (uint8_t)(1u << (pos & 7));
                if (pos + 1 > top)
                    top = (size_t)pos + 1;
            }
            off += (size_t)b;
            break;
        }
        case 0x1c: /* CONNECTION_CLOSE: error, frame type, reason */
            if (quic_varint(f, n, &off, &a) < 0 || quic_varint(f, n, &off, &b) < 0 ||
                quic_varint(f, n, &off, &c) < 0 || c > n - off)
                return -1;
            off += (size_t)c;
            break;
        default:
            return -1; /* no other frame may come in an Initial */
        }
    }
    while (*len < top && (have[*len >> 3] >> (*len & 7) & 1))
        (*len)++;
    return 0;
}
