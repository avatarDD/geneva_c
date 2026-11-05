/*
 * Cryptography for the extensions, C11 only (docs/EXT_ROADMAP.md, 6.5):
 * AES-128/256 (encryption direction only: ECB block, CTR, GCM), SHA-256,
 * HMAC-SHA256, HKDF (RFC 5869) and HKDF-Expand-Label of TLS 1.3.
 *
 * Uses: QUIC Initial protection (RFC 9001, RFC 9369), MTProto detection
 * (AES-256-CTR), the obfuscation of X13. None of it protects secrets of
 * the user: the QUIC Initial keys are public by design. The code is plain
 * and table-based, not constant-time; tags are still compared in constant
 * time and key schedules are wiped by the callers that own them.
 *
 * Left out by "make EXT_CRYPTO=0" together with QUIC decryption.
 */
#ifndef GENEVA_EXT_CRYPTO_H
#define GENEVA_EXT_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

/* ---- AES ----------------------------------------------------------------- */

typedef struct {
    uint32_t rk[60]; /* round keys */
    int rounds;      /* 10 (AES-128) or 14 (AES-256) */
} aes_ctx;

/* key_len 16 or 32. Returns 0, or -1 for another length. */
int aes_init(aes_ctx *c, const uint8_t *key, size_t key_len);
void aes_encrypt_block(const aes_ctx *c, const uint8_t in[16], uint8_t out[16]);
/* CTR mode with a 128-bit big-endian counter block: out = in ^ keystream.
 * in and out may be the same buffer. ctr is advanced. */
void aes_ctr(const aes_ctx *c, uint8_t ctr[16], const uint8_t *in, uint8_t *out, size_t n);

/* ---- GCM (NIST SP 800-38D), 96-bit IV, 128-bit tag ------------------------ */

typedef struct {
    aes_ctx aes;
    uint8_t h[16]; /* E(K, 0) */
} gcm_ctx;

int gcm_init(gcm_ctx *g, const uint8_t *key, size_t key_len);
void gcm_encrypt(const gcm_ctx *g, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *in,
                 uint8_t *out, size_t n, uint8_t tag[16]);
/* Returns 0 and the plaintext in out when the tag matches, else -1 (out
 * then holds garbage the caller must not use). */
int gcm_decrypt(const gcm_ctx *g, const uint8_t iv[12], const uint8_t *aad, size_t aad_len, const uint8_t *in,
                uint8_t *out, size_t n, const uint8_t tag[16]);

/* ---- SHA-256, HMAC, HKDF ------------------------------------------------- */

typedef struct {
    uint32_t h[8];
    uint64_t len; /* bytes so far */
    uint8_t buf[64];
    size_t nbuf;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t n);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t n, uint8_t out[32]);

void hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len, uint8_t out[32]);
void hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]);
/* out_len <= 255 * 32. Returns 0, or -1 when out_len is too large. */
int hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t *out, size_t out_len);
/* TLS 1.3 HKDF-Expand-Label(secret, "tls13 " + label, context, out_len). */
int hkdf_expand_label(const uint8_t secret[32], const char *label, const uint8_t *ctx, size_t ctx_len,
                      uint8_t *out, size_t out_len);

/* ---- helpers ------------------------------------------------------------- */

/* 0 when equal; the time does not depend on where the bytes differ. */
int ct_memcmp(const void *a, const void *b, size_t n);
/* memset that the compiler does not remove. */
void secure_zero(void *p, size_t n);

#endif
