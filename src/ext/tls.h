/*
 * TLS ClientHello reading for the extensions (docs/EXT_ROADMAP.md, J4): the
 * server name of a ClientHello that may come cut short, in TLS records (TCP)
 * or as a bare handshake message (the CRYPTO stream of QUIC). Bounds are
 * checked on every read; nothing is allocated.
 */
#ifndef GENEVA_EXT_TLS_H
#define GENEVA_EXT_TLS_H

#include <stddef.h>
#include <stdint.h>

enum {
    TLS_NOT_CH = -1,  /* not a ClientHello */
    TLS_NO_SNI = 0,   /* a complete ClientHello without server_name */
    TLS_SNI = 1,      /* found: the name is in out */
    TLS_PARTIAL = 2,  /* a ClientHello cut before its server_name (or before its end) */
};

/* A handshake message (type 1, 24-bit length, body). The name is copied to
 * out as a NUL-terminated string (cap bytes; longer names are refused as
 * TLS_NOT_CH). *msg_len, when not NULL, gets the full message length from
 * its header. */
int tls_hs_sni(const uint8_t *p, size_t n, char *out, size_t cap, size_t *msg_len);

/* The same over TLS records (content type 22): the handshake bytes of
 * consecutive records are joined in hs (hs_cap bytes, the caller's scratch;
 * 16 KB holds any ClientHello) first, so a ClientHello split into several
 * records is read too. */
int tls_rec_sni(const uint8_t *p, size_t n, char *out, size_t cap, uint8_t *hs, size_t hs_cap);

/* ---- tls_mod (J3) and genhost (J5) ---------------------------------------- */

enum { TLSMOD_RND = 1, TLSMOD_RNDSNI = 2, TLSMOD_SNI = 4, TLSMOD_DUPSID = 8, TLSMOD_PADENCAP = 16 };

typedef struct {
    unsigned mod;
    char sni[256];
} tls_modspec;

/* zapret2's TLSMod_parse_list: "rnd,rndsni,sni=NAME,dupsid,padencap,none".
 * Returns 0 or -1. */
int tls_mod_parse(const char *list, tls_modspec *m);
/* zapret2's TLSMod on the fake ClientHello record in fake (*len bytes, cap
 * the buffer: room for a longer SNI and the padding). payload, when not
 * NULL, is the client's own ClientHello (dupsid copies its session id,
 * padencap makes the fake's lengths cover it). Returns 0, or -1 when the
 * fake cannot take the mods (then it is not to be used as changed). */
int tls_mod_apply(const tls_modspec *m, const uint8_t *payload, size_t plen, uint8_t *fake, size_t *len, size_t cap);

/* zapret2's genhost: a random host name of len characters, ending in
 * template when there is one ("h82aj.google.com"); out holds len + 1. */
void tls_genhost(size_t len, const char *tmpl, char *out);

#endif
