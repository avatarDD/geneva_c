/*
 * L7 recognition of the extensions (docs/EXT_ROADMAP.md, E1, E2, E5): the
 * protocols and payload types of zapret2 (nfq2/protocol.c, MIT, see
 * docs/EXT.md) with the same names, order and checks, so that
 * "--payload=..." and "--filter-l7=..." lists mean the same here.
 *
 * Pure functions over caller buffers; every length is checked.
 */
#ifndef GENEVA_EXT_L7_H
#define GENEVA_EXT_L7_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

enum {
    L7_ALL = 0, L7_UNKNOWN, L7_KNOWN, L7_HTTP, L7_TLS, L7_DTLS, L7_QUIC, L7_WIREGUARD, L7_DHT, L7_DISCORD,
    L7_STUN, L7_XMPP, L7_DNS, L7_MTPROTO, L7_BT, L7_UTP_BT,
    L7_LAST
};

enum {
    L7P_ALL = 0, L7P_UNKNOWN, L7P_EMPTY, L7P_KNOWN, L7P_IPV4, L7P_IPV6, L7P_ICMP, L7P_HTTP_REQ, L7P_HTTP_REPLY,
    L7P_TLS_CLIENT_HELLO, L7P_TLS_SERVER_HELLO, L7P_DTLS_CLIENT_HELLO, L7P_DTLS_SERVER_HELLO, L7P_QUIC_INITIAL,
    L7P_WIREGUARD_INITIATION, L7P_WIREGUARD_RESPONSE, L7P_WIREGUARD_COOKIE, L7P_WIREGUARD_KEEPALIVE,
    L7P_WIREGUARD_DATA, L7P_DHT, L7P_DISCORD_IP_DISCOVERY, L7P_STUN, L7P_XMPP_STREAM, L7P_XMPP_STARTTLS,
    L7P_XMPP_PROCEED, L7P_XMPP_FEATURES, L7P_DNS_QUERY, L7P_DNS_RESPONSE, L7P_MTPROTO_INITIAL,
    L7P_BT_HANDSHAKE, L7P_UTP_BT_HANDSHAKE,
    L7P_LAST
};

const char *l7_proto_name(int l7);   /* NULL when out of range */
const char *l7_payload_name(int l7p);
int l7_proto_by_name(const char *s); /* -1 when unknown */
int l7_payload_by_name(const char *s);

/* A filter is a bit set of names; 0 is "all" (zapret2's l7_*_match). */
int l7_proto_match(int l7, uint64_t filter);
int l7_payload_match(int l7p, uint64_t filter);
/* "tls_client_hello,http_req" (a "~" in front negates the whole list into
 * *neg). Returns 0, or -1 with a message. */
int l7_payload_list(const char *s, uint64_t *set, int *neg, sbuf *err);
int l7_proto_list(const char *s, uint64_t *set, int *neg, sbuf *err);

/* Which payload a packet carries, as nfqws2 probes it. tcp: TCP (else
 * UDP); from_server: the packet goes from the server to the client;
 * first_data: the client's first data packet (relative seq 1), where
 * MTProto is tried. *l7 is the flow's protocol: when L7_UNKNOWN it becomes
 * the probe's. disable: payload types not to recognize
 * (--ext-payload-disable). Returns the payload type (L7P_UNKNOWN when
 * nothing matched, L7P_EMPTY for no data). */
int l7_probe(const uint8_t *d, size_t n, int tcp, int from_server, int first_data, uint64_t disable, int *l7);

/* The checks, one per payload type */
int l7_is_http(const uint8_t *d, size_t n);
int l7_is_http_reply(const uint8_t *d, size_t n);
int l7_is_tls_hello(const uint8_t *d, size_t n, uint8_t type, int partial_ok); /* record + handshake */
int l7_is_tls_hs_hello(const uint8_t *d, size_t n, uint8_t type, int partial_ok); /* handshake only */
int l7_is_quic_initial(const uint8_t *d, size_t n);
int l7_is_xmpp_stream(const uint8_t *d, size_t n);
int l7_is_dns_query(const uint8_t *d, size_t n);
int l7_is_dns_response(const uint8_t *d, size_t n);
int l7_is_dht(const uint8_t *d, size_t n);
int l7_is_stun(const uint8_t *d, size_t n);
int l7_is_mtproto(const uint8_t *d, size_t n); /* 0 in an EXT_CRYPTO=0 build */
int l7_is_dtls(const uint8_t *d, size_t n);

/* TLS record and handshake lengths (the caller made sure the header is
 * there: 5 bytes for a record, 4 for a handshake) */
size_t l7_tls_record_len(const uint8_t *d);
size_t l7_tls_hs_len(const uint8_t *d);
/* Offset of the extensions length field of a record (TLSFindExtLen) */
int l7_tls_ext_len_off(const uint8_t *d, size_t n, size_t *off);
/* An extension of a ClientHello/ServerHello, in a record or a bare
 * handshake message (partial_ok: the message may be cut) */
int l7_tls_find_ext(const uint8_t *d, size_t n, uint16_t type, const uint8_t **ext, size_t *len, int partial_ok);
int l7_tls_hs_find_ext(const uint8_t *d, size_t n, uint16_t type, const uint8_t **ext, size_t *len,
                       int partial_ok);
/* server_name: moves *ext to the name, *slen its length */
int l7_tls_sni_host(const uint8_t **ext, size_t *elen, size_t *slen);

/* The host name, lowercased into out (cap > 0): HTTP "Host:", TLS SNI of a
 * record or of a bare handshake message (QUIC). Return 1 when found. */
int l7_http_host(const uint8_t *d, size_t n, char *out, size_t cap);
int l7_tls_host(const uint8_t *d, size_t n, char *out, size_t cap, int partial_ok);
int l7_tls_hs_host(const uint8_t *d, size_t n, char *out, size_t cap, int partial_ok);
/* A header value ("\nLocation:"), lowercased */
int l7_http_header(const uint8_t *d, size_t n, const char *hdr, char *out, size_t cap);
int l7_http_reply_code(const uint8_t *d, size_t n); /* -1 when not a reply */
/* A 302/307 to another second-level domain than host (zapret2's
 * HttpReplyLooksLikeDPIRedirect) */
int l7_http_dpi_redirect(const uint8_t *d, size_t n, const char *host);

/* The N-th level domain of dom (FindNLD): *p and *len, 1 when it exists */
int l7_find_nld(const uint8_t *dom, size_t dlen, int level, const uint8_t **p, size_t *len);

/* The CRYPTO frame of a defragmented QUIC Initial (l7_quic_defrag) when it
 * starts a ClientHello: the handshake message's offset and length */
int l7_quic_crypto_hello(const uint8_t *d, size_t n, size_t *off, size_t *len);
/* zapret2's QUICDefragCrypto: the CRYPTO frames of decrypted Initial
 * frames into out as one CRYPTO frame (type 6, offset 0, 8-byte length)
 * followed by the data; *full when the pieces cover [0, end) without a
 * gap. *outlen is the buffer size in, the length out. Returns 1 when
 * CRYPTO frames were found, 0 when not or the frames are malformed. */
int l7_quic_defrag(const uint8_t *clean, size_t n, uint8_t *out, size_t *outlen, int *full);
/* zapret2's QUICDraftVersion: 0 when the version is not one it knows */
int l7_quic_draft(uint32_t version);

#endif
