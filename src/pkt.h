/*
 * Packet model. A packet is parsed into header fields plus an L4 payload and
 * rebuilt on demand. Field access mirrors Geneva's layers package: the same
 * protocol and field names, the same value types (integers, or strings for
 * flags, addresses, payloads and options) and the same rules for which length
 * and checksum fields scapy would recompute.
 *
 * An unmodified packet is emitted byte-for-byte as it arrived.
 */
#ifndef GENEVA_PKT_H
#define GENEVA_PKT_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define PKT_MAX 65535
#define TCP_MAX_OPTS 40

/* Layer identifiers. IPv6 is an addition over Geneva. */
typedef enum {
    LAYER_NONE = -1,
    LAYER_IP = 0,
    LAYER_TCP,
    LAYER_UDP,
    LAYER_DNS,
    LAYER_DNSQR,
    LAYER_IPV6,
    LAYER_COUNT
} layer_id;

/* Fields that are recomputed when the packet is built, unless a strategy
 * wrote them explicitly (tamper IP:chksum etc.). */
enum {
    AUTO_IP_LEN = 1 << 0,
    AUTO_IP_CSUM = 1 << 1,
    AUTO_IP_IHL = 1 << 2,
    AUTO_TCP_DOFS = 1 << 3,
    AUTO_TCP_CSUM = 1 << 4,
    AUTO_UDP_LEN = 1 << 5,
    AUTO_UDP_CSUM = 1 << 6,
    AUTO_V6_PLEN = 1 << 7,
};

typedef struct {
    uint8_t kind;
    uint8_t len; /* data length (without kind/len bytes) */
    uint8_t data[38];
} tcp_opt;

typedef struct gpkt {
    int ipver; /* 4 or 6 */

    /* IPv4 header */
    uint8_t version, ihl, tos, ttl, proto, ipflags;
    uint16_t iplen, id, frag, ipsum;
    uint8_t ipopts[40];
    uint8_t ipopts_len;

    /* IPv6 header (version shared with v4) */
    uint8_t tc, nh, hlim;
    uint32_t fl;
    uint16_t plen;
    uint8_t *ext; /* raw extension headers */
    size_t ext_len;
    uint8_t l4proto; /* final next-header / protocol */

    uint8_t src[16], dst[16];

    /* L4 */
    layer_id l4; /* LAYER_TCP, LAYER_UDP or LAYER_NONE */
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t dataofs, reserved;
    uint16_t tcpflags; /* 9 bits: FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32 ECE=64 CWR=128 NS=256 */
    uint16_t window, l4sum, urgptr, udplen;
    tcp_opt opts[TCP_MAX_OPTS];
    int nopts;
    uint8_t *opts_tail; /* unparseable trailing option bytes, re-emitted verbatim */
    size_t opts_tail_len;

    /* payload after the L4 header, or the whole IP payload when l4 == NONE */
    uint8_t *payload;
    size_t payload_len;

    unsigned auto_fields;
    int dirty;    /* any change since parsing */
    uint8_t *raw; /* original bytes, emitted while !dirty */
    size_t raw_len;

    double sleep; /* seconds to delay before sending (sleep action) */
} gpkt;

/* Field values: integer or string, like Geneva's Python values. */
typedef struct {
    int is_str;
    int64_t i;
    char *s; /* owned */
} gval;

void gval_int(gval *v, int64_t i);
void gval_str(gval *v, const char *s);
void gval_strn(gval *v, const char *s, size_t n);
void gval_free(gval *v);
void gval_copy(gval *dst, const gval *src);
int gval_eq(const gval *a, const gval *b);
/* String form used in strategy text and logs. */
void gval_print(sbuf *out, const gval *v);

/* ---- packets ------------------------------------------------------------- */

gpkt *pkt_parse(const uint8_t *data, size_t len);
gpkt *pkt_copy(const gpkt *p);
void pkt_free(gpkt *p);
/* Serializes into out (cap bytes). Returns length or 0 on failure. */
size_t pkt_build(gpkt *p, uint8_t *out, size_t cap);
/* Convenience: build into a freshly allocated buffer. */
uint8_t *pkt_bytes(gpkt *p, size_t *len);
/* Human-readable one-liner like Geneva's Packet.__str__. */
void pkt_describe(const gpkt *p, sbuf *out);

/* Layer presence and field access by Geneva names. */
layer_id layer_by_name(const char *name);
const char *layer_name(layer_id id);
int pkt_has_layer(const gpkt *p, layer_id id);
/* Fields of a layer in Geneva order; NULL-terminated. */
const char *const *layer_fields(layer_id id);
int layer_has_field(layer_id id, const char *field);

/* Returns 0 on success, -1 if the layer/field is absent. */
int pkt_get(const gpkt *p, layer_id layer, const char *field, gval *out);
/* Returns 0 on success, -1 if the value cannot be applied. */
int pkt_set(gpkt *p, layer_id layer, const char *field, const gval *v);
/* Random value for a field (Geneva's generators / scapy fuzz). */
int field_gen(layer_id layer, const char *field, gval *out);
/* Parses the textual value of a field from a strategy string. */
int field_parse(layer_id layer, const char *field, const char *text, gval *out);

/* Field restrictions used by evolve (--protos, --fields, --disable-fields).
 * Messages about unknown names are appended to msg. */
int fields_restrict(const char *protos, const char *fields, const char *disabled, sbuf *msg);
void fields_reset_restrictions(void);
int layer_is_allowed(layer_id id);
int field_is_allowed(layer_id id, const char *field);
size_t layer_allowed_fields(layer_id id, const char **out, size_t cap);

/* DNS query compression (tamper DNS:qd:compress). */
int pkt_dns_compress(gpkt *p);

/* TCP flags <-> scapy-style strings ("SA", "PA", "FRAPUN"). */
void tcp_flags_str(uint16_t flags, char *out);
int tcp_flags_parse(const char *s, uint16_t *out);
/* IPv4 flags <-> "DF", "MF+DF", "evil". */
void ip_flags_str(uint8_t flags, char *out);
int ip_flags_parse(const char *s, uint8_t *out);

/* Internet checksum helpers (exported for tests and the censor). */
uint16_t inet_csum(const uint8_t *p, size_t n, uint32_t init);
void pkt_mark_dirty(gpkt *p);
/* Replace the L4 payload. */
void pkt_set_payload(gpkt *p, const uint8_t *data, size_t len);

#endif
