/* Cryptography, QUIC Initial and TLS ClientHello reading of the extensions:
 * published test vectors and real client packets (tests/data/zapret2). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ext.h"
#  if GENEVA_EXT_CRYPTO
#    include "ext/crypto.h"
#  endif
#  include "ext/quic.h"
#  include "ext/tls.h"

#if GENEVA_EXT_CRYPTO
static size_t unhex(const char *h, uint8_t *out, size_t cap)
{
    long n = hex_decode(h, out, cap);
    CHECK(n >= 0);
    return n > 0 ? (size_t)n : 0;
}

static int eqhex(const uint8_t *p, size_t n, const char *h)
{
    uint8_t want[512];
    size_t wn = unhex(h, want, sizeof(want));
    if (wn != n || memcmp(p, want, n)) {
        t_dump("got", p, n);
        t_dump("want", want, wn);
        return 0;
    }
    return 1;
}

static void test_aes_gcm(void)
{
    uint8_t k[32], in[64], out[64], iv[12], aad[32], tag[16];
    size_t n, an;
    aes_ctx a;
    gcm_ctx g;

    t_current = "AES (FIPS-197 C.1, C.3)";
    unhex("000102030405060708090a0b0c0d0e0f", k, 16);
    unhex("00112233445566778899aabbccddeeff", in, 16);
    CHECK_INT(aes_init(&a, k, 16), 0);
    aes_encrypt_block(&a, in, out);
    CHECK(eqhex(out, 16, "69c4e0d86a7b0430d8cdb78070b4c55a"));
    unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", k, 32);
    CHECK_INT(aes_init(&a, k, 32), 0);
    aes_encrypt_block(&a, in, out);
    CHECK(eqhex(out, 16, "8ea2b7ca516745bfeafc49904b496089"));
    CHECK_INT(aes_init(&a, k, 24), -1);

    t_current = "AES-CTR (SP 800-38A F.5.1)";
    {
        uint8_t ctr[16];
        unhex("2b7e151628aed2a6abf7158809cf4f3c", k, 16);
        unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", ctr, 16);
        n = unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51", in, sizeof(in));
        aes_init(&a, k, 16);
        aes_ctr(&a, ctr, in, out, n);
        CHECK(eqhex(out, n, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"));
    }

    t_current = "GCM (McGrew-Viega test cases 1, 2, 4)";
    memset(k, 0, 16);
    memset(iv, 0, 12);
    gcm_init(&g, k, 16);
    gcm_encrypt(&g, iv, NULL, 0, NULL, NULL, 0, tag);
    CHECK(eqhex(tag, 16, "58e2fccefa7e3061367f1d57a4e7455a"));
    memset(in, 0, 16);
    gcm_encrypt(&g, iv, NULL, 0, in, out, 16, tag);
    CHECK(eqhex(out, 16, "0388dace60b6a392f328c2b971b2fe78"));
    CHECK(eqhex(tag, 16, "ab6e47d42cec13bdf53a67b21257bddf"));
    unhex("feffe9928665731c6d6a8f9467308308", k, 16);
    unhex("cafebabefacedbaddecaf888", iv, 12);
    n = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39", in, sizeof(in));
    an = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, sizeof(aad));
    gcm_init(&g, k, 16);
    gcm_encrypt(&g, iv, aad, an, in, out, n, tag);
    CHECK(eqhex(out, n, "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac"
                        "84aa051ba30b396a0aac973d58e091"));
    CHECK(eqhex(tag, 16, "5bc94fbc3221a5db94fae95ae7121a47"));
    {
        uint8_t back[64];
        CHECK_INT(gcm_decrypt(&g, iv, aad, an, out, back, n, tag), 0);
        CHECK(!memcmp(back, in, n));
        tag[3] ^= 1;
        CHECK_INT(gcm_decrypt(&g, iv, aad, an, out, back, n, tag), -1);
    }
}

static void test_sha_hkdf(void)
{
    uint8_t d[64], key[32], salt[16], info[16], okm[64], prk[32];
    size_t kn, sn, in;

    t_current = "SHA-256 (FIPS 180-4 examples)";
    sha256("abc", 3, d);
    CHECK(eqhex(d, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    sha256("", 0, d);
    CHECK(eqhex(d, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    {
        sha256_ctx c;
        char a[1000];
        memset(a, 'a', sizeof(a));
        sha256_init(&c);
        for (int i = 0; i < 1000; i++)
            sha256_update(&c, a, sizeof(a));
        sha256_final(&c, d);
        CHECK(eqhex(d, 32, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
    }
    sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, d);
    CHECK(eqhex(d, 32, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    t_current = "HMAC-SHA256 (RFC 4231 cases 1, 2)";
    kn = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", key, sizeof(key));
    hmac_sha256(key, kn, (const uint8_t *)"Hi There", 8, d);
    CHECK(eqhex(d, 32, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28, d);
    CHECK(eqhex(d, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    t_current = "HKDF (RFC 5869 case 1)";
    kn = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", key, sizeof(key));
    sn = unhex("000102030405060708090a0b0c", salt, sizeof(salt));
    in = unhex("f0f1f2f3f4f5f6f7f8f9", info, sizeof(info));
    hkdf_extract(salt, sn, key, kn, prk);
    CHECK(eqhex(prk, 32, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    CHECK_INT(hkdf_expand(prk, info, in, okm, 42), 0);
    CHECK(eqhex(okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    CHECK_INT(hkdf_expand(prk, info, in, okm, 255 * 32 + 1), -1);

    t_current = "ct_memcmp";
    CHECK_INT(ct_memcmp("abcd", "abcd", 4), 0);
    CHECK(ct_memcmp("abcd", "abce", 4) != 0);
}

/* RFC 9001 A.1: keys of the client Initial for DCID 0x8394c8f03e515708 */
static void test_quic_keys(void)
{
    static const uint8_t salt[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                     0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    uint8_t dcid[8], initial[32], client[32], key[16], iv[12], hp[16];
    t_current = "QUIC Initial keys (RFC 9001 A.1)";
    unhex("8394c8f03e515708", dcid, sizeof(dcid));
    hkdf_extract(salt, sizeof(salt), dcid, sizeof(dcid), initial);
    CHECK(eqhex(initial, 32, "7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"));
    CHECK_INT(hkdf_expand_label(initial, "client in", NULL, 0, client, 32), 0);
    CHECK(eqhex(client, 32, "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
    hkdf_expand_label(client, "quic key", NULL, 0, key, 16);
    hkdf_expand_label(client, "quic iv", NULL, 0, iv, 12);
    hkdf_expand_label(client, "quic hp", NULL, 0, hp, 16);
    CHECK(eqhex(key, 16, "1f369613dd76d5467730efcbe3b1a22d"));
    CHECK(eqhex(iv, 12, "fa044b2f42a3fd3b46fb255c"));
    CHECK(eqhex(hp, 16, "9f50449e04a0e810283a1e9933adedd2"));
}

#endif

static uint8_t *load(const char *name, size_t *n)
{
    char path[256];
    uint8_t *p;
    snprintf(path, sizeof(path), "tests/data/zapret2/%s", name);
    p = (uint8_t *)read_file(path, n);
    CHECK(p != NULL);
    return p;
}

/* The SNI of a client Initial file, or "" */
#if GENEVA_EXT_CRYPTO
static int quic_file_sni(const char *file, char *sni, size_t cap, uint32_t *ver)
{
    size_t n, slen;
    uint8_t *p = load(file, &n), frames[2048], stream[2048];
    quic_initial h;
    long fl;
    int r = TLS_NOT_CH;
    sni[0] = 0;
    if (!p)
        return r;
    fl = quic_initial_decrypt(p, n, &h, frames, sizeof(frames));
    *ver = h.version;
    if (fl >= 0 && quic_crypto_stream(frames, (size_t)fl, stream, sizeof(stream), &slen) == 0)
        r = tls_hs_sni(stream, slen, sni, cap, NULL);
    free(p);
    return r;
}

static void test_quic_files(void)
{
    char sni[256];
    uint32_t v = 0;
    quic_initial h;

    t_current = "QUIC v1 Initial (zapret2 www.google.com)";
    CHECK_INT(quic_file_sni("quic_initial_www_google_com.bin", sni, sizeof(sni), &v), TLS_SNI);
    CHECK_STR(sni, "www.google.com");
    CHECK_INT(v, QUIC_V1);
    t_current = "QUIC v1 Initial (zapret2 vk.com)";
    CHECK_INT(quic_file_sni("quic_initial_vk_com.bin", sni, sizeof(sni), &v), TLS_SNI);
    CHECK_STR(sni, "st.vk.com");
    t_current = "QUIC v2 Initial (RFC 9369 example.com)";
    CHECK_INT(quic_file_sni("quic2_example_com.bin", sni, sizeof(sni), &v), TLS_SNI);
    CHECK_STR(sni, "example.com");
    CHECK_INT(v, QUIC_V2);
    t_current = "QUIC Initial with a Kyber ClientHello over two packets";
    {
        int r = quic_file_sni("quic_initial_rutracker_org_kyber_1.bin", sni, sizeof(sni), &v);
        CHECK(r == TLS_SNI || r == TLS_PARTIAL); /* the first half may or may not hold the name */
        if (r == TLS_SNI)
            CHECK_STR(sni, "rutracker.org");
    }
    t_current = "QUIC: not an Initial";
    {
        size_t n;
        uint8_t *p = load("quic_short_header.bin", &n), frames[2048];
        if (p) {
            CHECK_INT(quic_is_initial(p, n, &h), 0);
            CHECK_INT(quic_initial_decrypt(p, n, &h, frames, sizeof(frames)), -1);
            free(p);
        }
    }
    t_current = "QUIC: a changed byte fails authentication";
    {
        size_t n;
        uint8_t *p = load("quic_initial_www_google_com.bin", &n), frames[2048];
        if (p) {
            p[n - 30] ^= 0x40;
            CHECK_INT(quic_initial_decrypt(p, n, &h, frames, sizeof(frames)), -1);
            /* every cut of the datagram is refused, none reads past it */
            for (size_t k = 0; k < n; k += 7)
                CHECK_INT(quic_initial_decrypt(p, k, &h, frames, sizeof(frames)), -1);
            free(p);
        }
    }
    t_current = "QUIC varint";
    {
        static const uint8_t b[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c, 0x9d, 0x7f, 0x3e, 0x7d, 0x7b, 0xbd, 0x25};
        size_t off = 0;
        uint64_t x;
        CHECK_INT(quic_varint(b, sizeof(b), &off, &x), 0);
        CHECK(x == 151288809941952652ull); /* RFC 9000 A.1 */
        CHECK_INT(quic_varint(b, sizeof(b), &off, &x), 0);
        CHECK_INT(x, 494878333);
        CHECK_INT(quic_varint(b, sizeof(b), &off, &x), 0);
        CHECK_INT(x, 15293);
        CHECK_INT(quic_varint(b, sizeof(b), &off, &x), 0);
        CHECK_INT(x, 37);
        CHECK_INT(quic_varint(b, sizeof(b), &off, &x), -1);
    }
}

#endif

static void test_tls_files(void)
{
    char sni[256];
    uint8_t hs[16384];
    size_t n;
    uint8_t *p;

    t_current = "TLS ClientHello (zapret2 iana.org)";
    p = load("tls_clienthello_iana_org.bin", &n);
    if (p) {
        CHECK_INT(tls_rec_sni(p, n, sni, sizeof(sni), hs, sizeof(hs)), TLS_SNI);
        CHECK_STR(sni, "iana.org");
        /* every prefix: partial until the name is in, never a wrong answer */
        for (size_t k = 1; k < n; k++) {
            int r = tls_rec_sni(p, k, sni, sizeof(sni), hs, sizeof(hs));
            CHECK(r == TLS_PARTIAL || (r == TLS_SNI && !strcmp(sni, "iana.org")));
        }
        free(p);
    }
    t_current = "TLS ClientHello with Kyber (zapret2 vk.com)";
    p = load("tls_clienthello_vk_com_kyber.bin", &n);
    if (p) {
        CHECK(n > 1500); /* does not fit one segment */
        CHECK_INT(tls_rec_sni(p, n, sni, sizeof(sni), hs, sizeof(hs)), TLS_SNI);
        CHECK_STR(sni, "vk.com");
        /* the same ClientHello as a bare handshake message */
        CHECK_INT(tls_hs_sni(p + 5, n - 5, sni, sizeof(sni), NULL), TLS_SNI);
        free(p);
    }
    t_current = "TLS: not a ClientHello";
    p = load("http_iana_org.bin", &n);
    if (p) {
        CHECK_INT(tls_rec_sni(p, n, sni, sizeof(sni), hs, sizeof(hs)), TLS_NOT_CH);
        free(p);
    }
    {
        static const uint8_t alert[] = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28};
        CHECK_INT(tls_rec_sni(alert, sizeof(alert), sni, sizeof(sni), hs, sizeof(hs)), TLS_NOT_CH);
    }
}

void suite_crypto(void)
{
#if GENEVA_EXT_CRYPTO
    test_aes_gcm();
    test_sha_hkdf();
    test_quic_keys();
    test_quic_files();
#endif
    test_tls_files();
}
#else
void suite_crypto(void) {}
#endif
