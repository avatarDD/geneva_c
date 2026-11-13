/*
 * "geneva blockcheck --ext" (X12b): zapret2's blockcheck2.sh with the
 * strategy grid of blockcheck2.d/standard, each line translated into a
 * geneva strategy (z2xlate.h) and probed through the evaluator.
 *
 * The grid is a port of the scripts' control flow: the same tests in the
 * same order, the same scan levels, the same "need_" shortcuts between the
 * scripts. The probing is a callback, so the tests drive the grid with an
 * oracle and without privileges.
 */
#ifndef GENEVA_EXT_BLOCKCHECK_H
#define GENEVA_EXT_BLOCKCHECK_H

#include <stdint.h>
#include <stdio.h>

#include "util.h"

enum { BC_VERYQUICK, BC_QUICK, BC_STANDARD, BC_FORCE };
enum { BC_HTTP, BC_TLS12, BC_TLS13, BC_HTTP3, BC_NTESTS };

/* One test of a strategy: 1 it worked, 0 it did not, -1 stop everything.
 * gen is the geneva strategy, NULL when the line has no translation or
 * does not parse (the test fails without a probe, as the zapret2 line
 * fails with a Lua error). */
typedef int (*bc_test_fn)(void *ctx, const char *nfqws2, const char *gen);

typedef struct {
    char *key;     /* "curl_test_http ipv4 : nfqws2 --payload=..." */
    char *line;    /* "curl_test_http ipv4 DOMAIN : nfqws2 --payload=..." */
    char *domain;
    char *test;    /* "curl_test_http ipv4" */
    char *value;   /* "nfqws2 --payload=...", "nfqws2 not working", ... */
    char *gen;     /* the geneva strategy of a working line */
} bc_entry;

/* X12c: the DNS check, the IP and port block tests (bcnet.c) */
#define BC_MAXIP 16
typedef char bc_ip[46];

typedef struct {
    int checked;
    int system_ok;      /* the system resolver answers */
    char pubdns[64];    /* the public DNS that answered ("": none) */
    int spoofed;        /* DNS_IS_SPOOFED */
    int secure;         /* the tests resolve through DoH (SECURE_DNS) */
    char doh[256];      /* ... this server */
} bc_dns_result;

typedef struct {
    char *kind;         /* "port" (check_domain_port_block) or "ip" (check_dpi_ip_block) */
    char *test;         /* ip: "curl_test_https_tls12", ... */
    int ipv;
    char *domain;       /* the name probed */
    char *ip;
    char *owner;        /* ip: the domain whose address ip is */
    int port;
    int ok;
    char *detail;
} bc_check;

typedef struct {
    /* blockcheck2's variables */
    int level;          /* SCANLEVEL (BC_STANDARD) */
    int min_ttl, max_ttl;         /* 1, 12; max 0: no TTL tests */
    int min_autottl, max_autottl; /* 1, 5; max 0: no autottl tests */
    int fake_repeats;   /* FAKE_REPEATS (1) */
    int multidisorder_legacy; /* MULTIDISORDER=multidisorder_legacy */
    unsigned skip;      /* scripts left out: bit i is the i-th (10-http-basic.sh is 0) */
    FILE *log;          /* the progress (stderr), NULL: none */

    bc_test_fn test;
    void *ctx;

    /* the state of a run */
    int ipv;
    const char *testf, *domain;
    char *strategy;     /* the first working line of the current test */
    int stopped;
    int ntests;         /* lines tried */
    /* the scripts' need_ variables across domains: -1 unset, 0, 1 */
    int need_multisplit, need_multidisorder, need_fake, need_fakedsplit, need_fakeddisorder,
        need_hostfakesplit;

    bc_entry *rep;      /* report_append's entries */
    size_t nrep;
    bc_dns_result dns;
    bc_check *chk;      /* port and IP block tests */
    size_t nchk;
} bc_run;

void bc_init(bc_run *b);
void bc_free(bc_run *b);

/* Only the scripts of list ("10,20,90": their numbers); 0, or -1 with err */
int bc_select_scripts(bc_run *b, const char *list, sbuf *err);

/* "curl_test_http", ... */
const char *bc_test_name(int test);

/* Runs every script for test on domain over IP version ipv, then
 * report_strategy: returns 1 when a strategy was found, 0 not, -1 stopped */
int bc_scripts(bc_run *b, int test, const char *domain, int ipv);

/* report_append */
void bc_report(bc_run *b, const char *domain, const char *value, const char *gen);

/* SUMMARY, and with several domains COMMON and COVERAGE, as blockcheck2
 * prints them; each working line is followed by "  geneva: STRATEGY" */
void bc_print(const bc_run *b, int ndomains, FILE *out);
/* the same as one JSON object */
void bc_print_json(const bc_run *b, int ndomains, sbuf *out);

/* ---- bcnet.c ---- */

/* One lookup of the A records of name: server NULL is the system resolver,
 * else that DNS server over UDP or TCP. Returns the number of addresses,
 * -1 without an answer. */
typedef int (*bc_lookup_fn)(void *ctx, const char *server, int tcp, const char *name, bc_ip *out, int max);

typedef struct {
    char **servers;     /* DNSCHECK_DNS */
    int nservers;
    char **domains;     /* DNSCHECK_DOM */
    int ndomains;
    bc_lookup_fn lookup;
    void *ctx;
    FILE *log;
} bc_dnscheck;

/* blockcheck2's check_dns_: the system resolver must answer, agree with a
 * public DNS on the domains, and give them different addresses; geneva
 * also asks the public DNS over TCP (an injection on the way answers UDP
 * only). Fills r (checked, system_ok, pubdns, spoofed); 0: DNS looks good */
int bc_check_dns(const bc_dnscheck *c, bc_dns_result *r);

/* the real lookups; ctx: a double, the timeout in seconds */
int bc_lookup(void *ctx, const char *server, int tcp, const char *name, bc_ip *out, int max);

/* DoH (RFC 8484, GET) through curl: the addresses of name for ipv, -1 with
 * err when there is no answer */
int bc_doh_query(const char *curl, const char *url, double timeout, const char *name, int ipv, bc_ip *out, int max,
                 sbuf *err);
/* a URL that can go into curl's command line */
int bc_doh_url_ok(const char *url);
/* base64url without padding; out has 4 * (n + 2) / 3 + 1 bytes */
void bc_base64url(const uint8_t *p, size_t n, char *out);

/* mdig_resolve_all with mdig_cache: the system resolver, or DoH */
typedef struct bc_rcache bc_rcache;
typedef struct {
    const char *curl, *doh; /* doh NULL: the system resolver */
    double timeout;
    bc_rcache *cache;
    size_t ncache;
} bc_resolver;
int bc_resolve_all(bc_resolver *r, const char *dom, int ipv, bc_ip *out, int max);
void bc_resolver_free(bc_resolver *r);

/* netcat -z: 1 when a TCP connection to ip:port opens in timeout */
int bc_port_open(const char *ip, uint16_t port, double timeout, char *detail, size_t cap);

/* adds a port or IP block test to the report */
void bc_add_check(bc_run *b, const bc_check *c);

int xcmd_blockcheck(int argc, char **argv);

#endif
