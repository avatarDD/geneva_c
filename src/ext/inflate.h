/*
 * Inflate of the extensions (docs/EXT_ROADMAP.md, C3): DEFLATE (RFC 1951)
 * in a gzip (RFC 1952) or zlib (RFC 1950) wrapper, for lists in .gz as
 * zapret2 reads them through zlib (inflateInit2 with 47: either wrapper,
 * the first member). No zlib: libc only. Every length is checked; a
 * corrupt or truncated stream is an error, never a read past the input.
 */
#ifndef GENEVA_EXT_INFLATE_H
#define GENEVA_EXT_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/* gzip magic 1f 8b */
int xinf_is_gzip(const uint8_t *d, size_t n);

/* Raw DEFLATE: decodes in into a growing buffer (*out, malloc'd, *outlen
 * bytes) of at most max bytes. *used: input bytes consumed. Returns 0, or
 * -1 on bad or truncated data, -2 when the output would pass max. */
int xinf_raw(const uint8_t *in, size_t n, size_t max, uint8_t **out, size_t *outlen, size_t *used);

/* A gzip or zlib stream (the first member), its CRC-32 or Adler-32
 * checked. Same returns as xinf_raw. */
int xinf_unwrap(const uint8_t *in, size_t n, size_t max, uint8_t **out, size_t *outlen);

uint32_t xinf_crc32(uint32_t crc, const uint8_t *d, size_t n);

#endif
