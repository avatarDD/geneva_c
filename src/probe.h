/*
 * Probes: one attempt to reach the censored resource, scored like the
 * client plugins of Geneva (plugins/NAME/client.py). Success is a complete
 * exchange, not a handshake: the whole HTTP response, the server's TLS
 * flight after ServerHello, a DNS answer that is not a known injection, the
 * expected TCP reply, or an external command that exits with 0.
 *
 * Sockets bind to local ports of the caller's block, so that the engine
 * applies the right strategy (see eng_slots in engine.h).
 */
#ifndef GENEVA_PROBE_H
#define GENEVA_PROBE_H

#include <stddef.h>
#include <stdint.h>

#include "plat.h"
#include "util.h"

typedef enum { PROBE_HTTP, PROBE_TLS, PROBE_DNS, PROBE_TCP, PROBE_EXEC, PROBE_EXTERNAL } probe_kind;

/* What happened; each outcome has Geneva's fitness (probe_fitness). */
typedef enum {
    PO_OK,           /* complete exchange: +400 */
    PO_RESET,        /* reset, refused, unreachable: -360 (Geneva's -90 x 4) */
    PO_INJECTED,     /* the censor's answer (block page, forged DNS): -360 */
    PO_CONN_TIMEOUT, /* no connection: -400 */
    PO_TIMEOUT,      /* connected, then silence: -480 (the strategy likely broke the stream) */
    PO_BROKEN,       /* incomplete or malformed answer: -480 */
    PO_FAILED,       /* exec: non-zero exit; other errors: -400 */
} probe_outcome;

const char *probe_outcome_name(probe_outcome o);
double probe_fitness(probe_outcome o);
int probe_kind_parse(const char *s, probe_kind *out);
const char *probe_kind_name(probe_kind k);

typedef struct {
    probe_kind kind;
    const char *host;        /* Host header, SNI, DNS name */
    const char *ip;          /* address to connect to (DNS: the resolver) */
    uint16_t port;
    struct sockaddr_storage addr; /* filled by probe_resolve() */
    int addrlen;
    double timeout;          /* seconds for the connection and for each wait for data */

    const char *path;        /* http: request path (default /) */
    const char *bad_word;    /* http: appended as ?q=WORD, like Geneva */
    const char *valid_contains;    /* http, tcp, exec: the answer must contain this */
    const char *injected_contains; /* http, tls, tcp, exec: the censor's answer contains this */
    size_t min_bytes;        /* http, tls, tcp: at least this much must arrive */
    size_t max_bytes;        /* http, tcp: enough; stop reading (default 4 MB) */

    int tls_version;         /* tls: 12, 13, or 0 for both */
    const char *alpn;        /* tls: default http/1.1 */

    int dns_tcp;             /* dns: over TCP */
    int dns_aaaa;            /* dns: ask for AAAA */
    const char *dns_expect;  /* dns: comma list; an answer must be one of these */
    const char *dns_bad;     /* dns: comma list of injected addresses */

    uint8_t *payload;        /* tcp: bytes to send */
    size_t payload_len;

    const char *cmd;         /* exec: command line ({lports}, {lport}, {host}, {ip}, {port}) */
} probe_cfg;

typedef struct {
    probe_outcome outcome;
    double fitness;
    size_t bytes;            /* bytes received */
    char detail[200];
} probe_res;

/* Local ports a probe may use: lo..hi, rotated through *next so that a new
 * connection does not reuse a port in TIME_WAIT. lo = 0: any port. */
typedef struct {
    uint16_t lo, hi;
    uint32_t next;
} probe_ports;

/* Resolves cfg->ip (or cfg->host) into cfg->addr. Returns 0 or -1 with a
 * message. */
int probe_resolve(probe_cfg *c, sbuf *err);

/* Runs one attempt (not for PROBE_EXTERNAL). */
void probe_run(const probe_cfg *c, probe_ports *lp, probe_res *r);

/* Escapes \r \n \t \\ \xHH, or "hex:..." for raw bytes. Returns 0 or -1. */
int probe_parse_payload(const char *s, uint8_t **out, size_t *len);

/* Pieces exported for the tests. */
size_t probe_client_hello(const char *sni, const char *alpn, int tls_version, uint8_t *buf, size_t cap);
size_t probe_dns_query(const char *name, int aaaa, uint16_t id, uint8_t *buf, size_t cap);
/* Parses a DNS response for query id: addresses go to out as text, one per
 * entry. Returns the number of addresses, or -1 for a malformed/other id
 * answer; *rcode gets the response code. */
int probe_dns_parse(const uint8_t *p, size_t n, uint16_t id, char out[][46], int max, int *rcode);
/* Substitutes {lports}, {lport}, {host}, {ip}, {port}. */
void probe_expand_cmd(const probe_cfg *c, const probe_ports *lp, sbuf *out);

#endif
