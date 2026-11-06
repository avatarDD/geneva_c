/*
 * Blobs of the extensions (docs/EXT_ROADMAP.md, J1, J2): named byte strings
 * the x-actions send as fakes or fill patterns with ("blob=fake_default_tls",
 * "pattern=0x1603", "seqovl=#fake_default_tls"), as zapret2's --blob.
 *
 *   --ext-blob NAME:0xHEX            the bytes of the hex string
 *   --ext-blob NAME:[+OFS]@FILE      a file from offset OFS (FILE alone too)
 *
 * Built in, made here rather than copied (decision 11.3 of the roadmap):
 *   fake_default_tls    a TLS 1.3 ClientHello for www.iana.org, 680 bytes,
 *                       ending in a padding extension (what tlsmod=padencap
 *                       grows)
 *   fake_default_http   a GET of http://www.iana.org/
 *   fake_default_quic   620 bytes: 0x40 and zeros, as zapret2's
 *   fake_quic_initial   a QUIC v1 Initial for www.iana.org, 1200 bytes,
 *                       encrypted (only in a build with EXT_CRYPTO)
 * The rest of zapret2's files/fake (BGP, ISAKMP, RDP, bitcoin) ships as
 * files in files/fake/ of this repository with zapret2's MIT notice; load
 * them with --ext-blob.
 *
 * The table is set up once by ext_activate() before any packet runs and is
 * read-only afterwards.
 */
#ifndef GENEVA_EXT_BLOB_H
#define GENEVA_EXT_BLOB_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define BLOB_NAME_MAX 64
#define BLOB_HEX_MAX (16 * 1024)    /* zapret2's MAX_BLOB_SIZE for hex strings */
#define BLOB_FILE_MAX (1024 * 1024) /* a file blob; zapret2 has no limit */

typedef struct {
    const uint8_t *data;
    size_t len;
} xblob;

/* The built-in blobs; drops the ones added before. */
void blob_reset(void);
/* --ext-blob SPEC. Returns 0, or -1 with a message (a name already
 * taken, a bad name, an unreadable file, bad hex). */
int blob_opt(const char *spec, sbuf *err);
/* NULL when there is no blob of that name. */
const xblob *blob_find(const char *name);
/* Frees every blob (tests, the end). */
void blob_free_all(void);

/* "0x..." into a fresh buffer (*out, owned by the caller). Returns 0, or
 * -1 when s is not hex of an even length or is longer than max bytes. An
 * empty "0x" gives 0 bytes. */
int blob_hex(const char *s, size_t max, uint8_t **out, size_t *len);
/* zapret2's is_identifier: a letter or "_", then letters, digits, "_". */
int blob_name_ok(const char *s);

/* The generators behind the built-ins (tests): a ClientHello record for
 * sni padded to total bytes (0: no padding), and a QUIC v1 Initial
 * datagram carrying a ClientHello for sni (0 without EXT_CRYPTO). The
 * random fields come from seed, so the same seed gives the same bytes. */
size_t blob_make_tls(const char *sni, size_t total, uint32_t seed, uint8_t *out, size_t cap);
size_t blob_make_quic(const char *sni, uint32_t seed, uint8_t *out, size_t cap);

#endif
