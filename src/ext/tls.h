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

#endif
