/*
 * "geneva blockcheck --ext" (X12c): blockcheck2.sh's checks around the
 * strategies - check_dns_ (the system resolver against public DNS),
 * SECURE_DNS with doh_find_working and doh_resolve, mdig_resolve_all with
 * its cache, and netcat_test of check_domain_port_block. curl does DoH, as
 * in blockcheck2; the rest is in C (no mdig, nslookup, ping or netcat).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ext/blockcheck.h"
#include "plat.h"
#include "probe.h"
#include "util.h"

#ifndef _WIN32
#  include <netdb.h>
#endif

/* ---- check_dns_ ---------------------------------------------------------------------- */

static int has_ip(const bc_ip *set, int n, const char *ip)
{
    for (int i = 0; i < n; i++)
        if (!strcmp(set[i], ip))
            return 1;
    return 0;
}

static void log_ips(FILE *log, const bc_ip *ips, int n)
{
    for (int i = 0; log && i < n; i++)
        fprintf(log, "%s\n", ips[i]);
}

static int cmp_ip(const void *a, const void *b) { return strcmp(a, b); }

int bc_check_dns(const bc_dnscheck *c, bc_dns_result *r)
{
    FILE *log = c->log;
    bc_ip probe[BC_MAXIP], *digs = NULL;
    int ndigs = 0, uniq = 0, ret = 1;

    r->checked = 1;
    r->system_ok = 0;
    r->spoofed = 0;
    r->pubdns[0] = 0;
    if (log)
        fprintf(log, "* checking DNS\n");
    if (c->lookup(c->ctx, NULL, 0, "iana.org", probe, BC_MAXIP) <= 0) {
        if (log)
            fprintf(log, "-- DNS is not working. It's either misconfigured or blocked or you don't have inet access.\n");
        return 1;
    }
    r->system_ok = 1;
    if (log)
        fprintf(log, "system DNS is working\n");
    /* find_working_public_dns: geneva has no ping, the answer is the test */
    for (int i = 0; i < c->nservers; i++)
        if (c->lookup(c->ctx, c->servers[i], 0, "iana.org", probe, BC_MAXIP) > 0) {
            snprintf(r->pubdns, sizeof(r->pubdns), "%s", c->servers[i]);
            break;
        }
    digs = xmalloc((size_t)(c->ndomains ? c->ndomains : 1) * BC_MAXIP * sizeof(bc_ip));
    if (r->pubdns[0]) {
        if (log)
            fprintf(log, "comparing system resolver to public DNS : %s\n", r->pubdns);
        for (int d = 0; d < c->ndomains; d++) {
            bc_ip sys[BC_MAXIP], pub[BC_MAXIP], tcp[BC_MAXIP];
            int ns = c->lookup(c->ctx, NULL, 0, c->domains[d], sys, BC_MAXIP);
            int np = c->lookup(c->ctx, r->pubdns, 0, c->domains[d], pub, BC_MAXIP);
            int nt, mismatch = 0, common = 0;
            ns = ns < 0 ? 0 : ns;
            np = np < 0 ? 0 : np;
            for (int i = 0; i < ns; i++)
                if (!has_ip(pub, np, sys[i]))
                    mismatch = 1;
            if (mismatch) {
                if (log) {
                    fprintf(log, "%s : MISMATCH\n-- system resolver :\n", c->domains[d]);
                    log_ips(log, sys, ns);
                    fprintf(log, "-- %s :\n", r->pubdns);
                    log_ips(log, pub, np);
                    fprintf(log, "-- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!\n"
                                 "-- DNS CHANGE OR DNSCRYPT MAY BE REQUIRED\n");
                }
                r->spoofed = 1;
                goto out;
            }
            /* geneva: the same server over TCP; no address in common is an
             * answer injected on the way (one in common: a DNS balancer) */
            nt = np ? c->lookup(c->ctx, r->pubdns, 1, c->domains[d], tcp, BC_MAXIP) : -1;
            for (int i = 0; i < nt; i++)
                if (has_ip(pub, np, tcp[i]))
                    common = 1;
            if (nt > 0 && !common) {
                if (log) {
                    fprintf(log, "%s : UDP AND TCP DIFFER\n-- %s over UDP :\n", c->domains[d], r->pubdns);
                    log_ips(log, pub, np);
                    fprintf(log, "-- %s over TCP :\n", r->pubdns);
                    log_ips(log, tcp, nt);
                    fprintf(log, "-- POSSIBLE DNS INJECTION ON THE WAY. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!\n"
                                 "-- DNS CHANGE OR DNSCRYPT MAY BE REQUIRED\n");
                }
                r->spoofed = 1;
                goto out;
            }
            if (log)
                fprintf(log, "%s : OK\n", c->domains[d]);
            memcpy(digs + ndigs, sys, (size_t)ns * sizeof(bc_ip));
            ndigs += ns;
        }
    } else {
        if (log)
            fprintf(log, "no working public DNS was found. looks like public DNS blocked.\n");
        for (int d = 0; d < c->ndomains; d++) {
            int ns = c->lookup(c->ctx, NULL, 0, c->domains[d], digs + ndigs, BC_MAXIP);
            ndigs += ns > 0 ? ns : 0;
        }
    }
    if (log) {
        fprintf(log, "checking resolved IP uniqueness for :");
        for (int d = 0; d < c->ndomains; d++)
            fprintf(log, " %s", c->domains[d]);
        fprintf(log, "\ncensor's DNS can return equal result for multiple blocked domains.\n");
    }
    if (!ndigs) {
        if (log)
            fprintf(log, "-- DNS is not working. It's either misconfigured or blocked or you don't have inet access.\n");
        goto out;
    }
    qsort(digs, (size_t)ndigs, sizeof(bc_ip), cmp_ip);
    for (int i = 0; i < ndigs; i++)
        uniq += !i || strcmp(digs[i], digs[i - 1]);
    if (uniq != ndigs) {
        if (log) {
            fprintf(log, "system dns resolver has returned equal IPs for some domains checked above (%d total, %d unique)\n"
                         "non-unique IPs :\n",
                    ndigs, uniq);
            for (int i = 1; i < ndigs; i++)
                if (!strcmp(digs[i], digs[i - 1]) && (i == 1 || strcmp(digs[i - 1], digs[i - 2])))
                    fprintf(log, "%s\n", digs[i]);
            fprintf(log, "-- POSSIBLE DNS HIJACK DETECTED. ZAPRET WILL NOT HELP YOU IN CASE DNS IS SPOOFED !!!\n"
                         "-- DNSCRYPT MAY BE REQUIRED\n");
        }
        r->spoofed = 1;
        goto out;
    }
    if (log)
        fprintf(log, "all resolved IPs are unique\n-- DNS looks good\n"
                     "-- NOTE this check is Russia targeted. In your country other domains may be blocked.\n");
    ret = 0;
out:
    free(digs);
    return ret;
}

/* ---- lookups --------------------------------------------------------------------------- */

static int system_lookup(const char *name, int family, bc_ip *out, int max)
{
    struct addrinfo hints, *res = NULL;
    int n = 0;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(name, NULL, &hints, &res) || !res)
        return -1;
    for (const struct addrinfo *a = res; a && n < max; a = a->ai_next) {
        bc_ip ip;
        const void *p;
        if (a->ai_family == AF_INET)
            p = &((const struct sockaddr_in *)a->ai_addr)->sin_addr;
        else if (a->ai_family == AF_INET6)
            p = &((const struct sockaddr_in6 *)a->ai_addr)->sin6_addr;
        else
            continue;
        if (inet_ntop(a->ai_family, p, ip, sizeof(ip)) && !has_ip(out, n, ip))
            memcpy(out[n++], ip, sizeof(ip));
    }
    freeaddrinfo(res);
    return n ? n : -1;
}

static int server_lookup(const char *server, int tcp, int aaaa, const char *name, double timeout, bc_ip *out,
                         int max)
{
    probe_cfg c;
    probe_ports lp = {0, 0, 0};
    probe_res r;
    sbuf err;
    int n = 0;
    memset(&c, 0, sizeof(c));
    c.kind = PROBE_DNS;
    c.host = name;
    c.ip = server;
    c.port = 53;
    c.timeout = timeout;
    c.dns_tcp = tcp;
    c.dns_aaaa = aaaa;
    c.dns_out = out;
    c.dns_out_max = max;
    c.dns_out_n = &n;
    sb_init(&err);
    if (probe_resolve(&c, &err) < 0) {
        sb_free(&err);
        return -1;
    }
    sb_free(&err);
    probe_run(&c, &lp, &r);
    return n ? n : -1;
}

int bc_lookup(void *ctx, const char *server, int tcp, const char *name, bc_ip *out, int max)
{
    double timeout = ctx ? *(const double *)ctx : 2;
    if (!server)
        return system_lookup(name, AF_INET, out, max);
    return server_lookup(server, tcp, 0, name, timeout, out, max);
}

/* ---- DoH ------------------------------------------------------------------------------- */

void bc_base64url(const uint8_t *p, size_t n, char *out)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)p[i] << 16 | (i + 1 < n ? (uint32_t)p[i + 1] << 8 : 0) | (i + 2 < n ? p[i + 2] : 0);
        out[o++] = t[v >> 18 & 63];
        out[o++] = t[v >> 12 & 63];
        if (i + 1 < n)
            out[o++] = t[v >> 6 & 63];
        if (i + 2 < n)
            out[o++] = t[v & 63];
    }
    out[o] = 0;
}

int bc_doh_url_ok(const char *url)
{
    /* it goes into a command line in double quotes, for sh and cmd.exe */
    if (!str_starts(url, "https://") && !str_starts(url, "http://"))
        return 0;
    for (const char *p = url; *p; p++)
        if (!strchr("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~:/?=&[]@+,;", *p))
            return 0;
    return 1;
}

int bc_doh_query(const char *curl, const char *url, double timeout, const char *name, int ipv, bc_ip *out, int max,
                 sbuf *err)
{
    uint8_t q[300];
    char b64[420], addrs[BC_MAXIP][46];
    size_t qn;
    sbuf cmd, res;
    int rc, rcode = 0, n;

    if (!bc_doh_url_ok(url)) {
        sb_printf(err, "bad DoH URL %s", url);
        return -1;
    }
    /* RFC 8484 4.1: the id is 0, for the caches */
    qn = probe_dns_query(name, ipv == 6, 0, q, sizeof(q));
    if (!qn) {
        sb_printf(err, "bad name %s", name);
        return -1;
    }
    bc_base64url(q, qn, b64);
    sb_init(&cmd);
    sb_init(&res);
    sb_printf(&cmd, "%s -s --max-time %g -H \"accept: application/dns-message\" \"%s%cdns=%s\"", curl, timeout, url,
              strchr(url, '?') ? '&' : '?', b64);
    rc = probe_spawn(cmd.data, timeout + 5, &res);
    if (rc != 0) {
        if (rc == -1 || rc == -2)
            sb_printf(err, rc == -1 ? "cannot run %s" : "%s ran over the time", curl);
        else
            sb_printf(err, "%s failed (exit %d)", curl, rc);
        n = -1;
    } else {
        n = probe_dns_parse((const uint8_t *)res.data, res.len, 0, addrs, BC_MAXIP, &rcode);
        if (n <= 0 || rcode) {
            sb_printf(err, n < 0 ? "no DNS answer" : "no addresses (rcode %d)", rcode);
            n = -1;
        } else {
            n = n < max ? n : max;
            for (int i = 0; i < n; i++)
                memcpy(out[i], addrs[i], sizeof(bc_ip));
        }
    }
    sb_free(&cmd);
    sb_free(&res);
    return n;
}

/* ---- mdig_resolve_all ------------------------------------------------------------------ */

struct bc_rcache {
    char *dom;
    int ipv, n;
    bc_ip ips[BC_MAXIP];
};

int bc_resolve_all(bc_resolver *r, const char *dom, int ipv, bc_ip *out, int max)
{
    bc_rcache *e;
    int n;
    for (size_t i = 0; i < r->ncache; i++)
        if (r->cache[i].ipv == ipv && !strcmp(r->cache[i].dom, dom)) {
            n = r->cache[i].n < max ? r->cache[i].n : max;
            memcpy(out, r->cache[i].ips, (size_t)n * sizeof(bc_ip));
            return n;
        }
    if (r->doh) {
        sbuf err;
        sb_init(&err);
        n = bc_doh_query(r->curl, r->doh, r->timeout, dom, ipv, out, max, &err);
        sb_free(&err);
    } else {
        n = system_lookup(dom, ipv == 6 ? AF_INET6 : AF_INET, out, max);
    }
    if (n <= 0)
        return -1; /* not cached, as mdig_cache */
    r->cache = xrealloc(r->cache, (r->ncache + 1) * sizeof(*r->cache));
    e = &r->cache[r->ncache++];
    e->dom = xstrdup(dom);
    e->ipv = ipv;
    e->n = n < BC_MAXIP ? n : BC_MAXIP;
    memcpy(e->ips, out, (size_t)e->n * sizeof(bc_ip));
    return n;
}

void bc_resolver_free(bc_resolver *r)
{
    for (size_t i = 0; i < r->ncache; i++)
        free(r->cache[i].dom);
    free(r->cache);
    r->cache = NULL;
    r->ncache = 0;
}

/* ---- netcat_test ----------------------------------------------------------------------- */

int bc_port_open(const char *ip, uint16_t port, double timeout, char *detail, size_t cap)
{
    probe_cfg c;
    probe_ports lp = {0, 0, 0};
    probe_res r;
    sbuf err;
    memset(&c, 0, sizeof(c));
    c.kind = PROBE_TCP;
    c.ip = ip;
    c.port = port;
    c.timeout = timeout;
    c.connect_only = 1;
    sb_init(&err);
    if (probe_resolve(&c, &err) < 0) {
        snprintf(detail, cap, "%s", err.data ? err.data : "bad address");
        sb_free(&err);
        return 0;
    }
    sb_free(&err);
    probe_run(&c, &lp, &r);
    snprintf(detail, cap, "%s", r.detail);
    return r.outcome == PO_OK;
}

void bc_add_check(bc_run *b, const bc_check *c)
{
    bc_check *e;
    b->chk = xrealloc(b->chk, (b->nchk + 1) * sizeof(*b->chk));
    e = &b->chk[b->nchk++];
    *e = *c;
    e->kind = xstrdup(c->kind);
    e->test = c->test ? xstrdup(c->test) : NULL;
    e->domain = xstrdup(c->domain);
    e->ip = xstrdup(c->ip);
    e->owner = c->owner ? xstrdup(c->owner) : NULL;
    e->detail = xstrdup(c->detail ? c->detail : "");
}
