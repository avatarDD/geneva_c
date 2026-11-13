/*
 * The autolist (autolist.h)
 */
#include "autolist.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "l7.h"
#include "log.h"
#include "sec_win.h"
#include "plat.h"
#include "util.h"

static char *g_debug; /* --hostlist-auto-debug */

int xah_debug_log(const char *path)
{
    FILE *f;
    free(g_debug);
    g_debug = NULL;
    if (!path)
        return 0;
    if (!(f = fopen(path, "ab")))
        return -1;
    fclose(f);
    g_debug = xstrdup(path);
    xsbx_file(path);
    return 0;
}

/* HOSTLIST_DEBUGLOG_APPEND: "dd.mm.yyyy hh:mm:ss : ..." */
static void debug(const char *fmt, ...) PRINTF_LIKE(1, 2);
static void debug(const char *fmt, ...)
{
    FILE *f;
    va_list ap;
    time_t now;
    struct tm t;
    if (!g_debug || !(f = fopen(g_debug, "ab")))
        return;
    time(&now);
#ifdef _WIN32
    localtime_s(&t, &now);
#else
    localtime_r(&now, &t);
#endif
    fprintf(f, "%02d.%02d.%04d %02d:%02d:%02d : ", t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min,
            t.tm_sec);
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}

static const char *pname(const xprofile *p) { return p->name ? p->name : "noname"; }

void xah_free(xprofile *p)
{
    for (size_t i = 0; i < p->nfails; i++)
        free(p->fails[i].host);
    free(p->fails);
    p->fails = NULL;
    p->nfails = 0;
}

static xahfail *fail_find(xprofile *p, const char *host)
{
    for (size_t i = 0; i < p->nfails; i++)
        if (!strcmp(p->fails[i].host, host))
            return &p->fails[i];
    return NULL;
}

static void fail_del(xprofile *p, xahfail *c)
{
    free(c->host);
    *c = p->fails[--p->nfails];
}

void xah_purge(xprofile *p, uint64_t now_ms)
{
    uint64_t now = now_ms / 1000;
    if (now == p->fails_purged)
        return;
    p->fails_purged = now;
    for (size_t i = 0; i < p->nfails;)
        if (now >= p->fails[i].expire) /* HostFailPoolPurge */
            fail_del(p, &p->fails[i]);
        else
            i++;
}

void xah_reset(xprofile *p, const char *host, const char *client, int l7)
{
    xahfail *c = host ? fail_find(p, host) : NULL;
    if (!c)
        return;
    fail_del(p, c);
    LOGD("autolist", "profile %d (%s): %s: fail counter reset, the site works", p->n, pname(p), host);
    debug("%s : profile %d (%s) : client %s : proto %s : fail counter reset. website is working.", host, p->n,
          pname(p), client, l7_proto_name(l7));
}

void xah_failed(xprofile *p, const char *host, int host_ip, const char *client, int l7, uint64_t now_ms)
{
    xahfail *c = fail_find(p, host);
    int excluded = 0;
    if (!c) {
        p->fails = xrealloc(p->fails, sizeof(*p->fails) * (p->nfails + 1));
        c = &p->fails[p->nfails++];
        c->host = xstrdup(host);
        c->counter = 0;
        c->expire = now_ms / 1000 + (uint64_t)p->ah_fail_time;
    }
    c->counter++;
    LOGD("autolist", "profile %d (%s): %s: fail counter %d/%d", p->n, pname(p), host, c->counter,
         p->ah_fail_threshold);
    debug("%s : profile %d (%s) : client %s : proto %s : fail counter %d/%d", host, p->n, pname(p), client,
          l7_proto_name(l7), c->counter, p->ah_fail_threshold);
    if (c->counter < p->ah_fail_threshold)
        return;
    fail_del(p, c);
    /* checked again: another flow may have added it meanwhile */
    if (!xprof_hosts(p, host, host_ip, &excluded) && !excluded) {
        LOGI("autolist", "profile %d (%s): adding %s to %s", p->n, pname(p), host, p->ahl->name);
        debug("%s : profile %d (%s) : client %s : proto %s : adding to %s", host, p->n, pname(p), client,
              l7_proto_name(l7), p->ahl->path);
        if (xlist_append(p->ahl, host) < 0)
            LOGE("autolist", "cannot write %s", p->ahl->name);
    } else {
        LOGD("autolist", "profile %d (%s): not adding %s (a duplicate)", p->n, pname(p), host);
        debug("%s : profile %d (%s) : client %s : proto %s : NOT adding, duplicate detected", host, p->n, pname(p),
              client, l7_proto_name(l7));
    }
}

/* "ip:port" of the client, for the debug log */
static void client_str(const ct_flow *f, char *out, size_t cap)
{
    char a[64];
    *out = 0;
    if (!g_debug)
        return;
    if (!inet_ntop(f->ver == 6 ? AF_INET6 : AF_INET, f->cli, a, sizeof(a)))
        return;
    snprintf(out, cap, f->ver == 6 ? "[%s]:%u" : "%s:%u", a, f->cport);
}

/* seq_within: a <= x <= b with wrap */
static int seq_within(uint32_t x, uint32_t a, uint32_t b) { return x - a <= b - a; }

static void put16(uint8_t *p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    put16(p, v >> 16);
    put16(p + 2, v & 0xffff);
}

size_t xah_rst(const gpkt *p, const ct_flow *f, uint8_t *out)
{
    size_t ih = p->ipver == 6 ? 40 : 20;
    uint8_t *t = out + ih;
    uint32_t sum = 0;
    if (p->l4 != LAYER_TCP)
        return 0;
    memset(out, 0, ih + 20);
    if (p->ipver == 6) {
        uint32_t fl = f && f->server.ip6flow ? f->server.ip6flow : 0x60000000u;
        put32(out, fl);
        put16(out + 4, 20);
        out[6] = 6;
        out[7] = p->hlim;
        memcpy(out + 8, p->dst, 16);
        memcpy(out + 24, p->src, 16);
        for (int i = 8; i < 40; i += 2)
            sum += (uint32_t)(out[i] << 8 | out[i + 1]);
    } else {
        out[0] = 0x45;
        out[1] = p->tos;
        put16(out + 2, 40);
        if (p->raw && p->raw_len >= 20)
            out[6] = p->raw[6] & 0xE0; /* the flags, no offset */
        out[8] = p->ttl;
        out[9] = 6;
        memcpy(out + 12, p->dst, 4);
        memcpy(out + 16, p->src, 4);
        put16(out + 10, inet_csum(out, 20, 0));
        for (int i = 12; i < 20; i += 2)
            sum += (uint32_t)(out[i] << 8 | out[i + 1]);
    }
    put16(t, p->dport);
    put16(t + 2, p->sport);
    put32(t + 4, p->ack); /* reverse_tcp: seq and ack swapped */
    put32(t + 8, p->seq);
    t[12] = 5 << 4;
    t[13] = 0x04; /* RST */
    put16(t + 14, f ? f->server.winsize : 0);
    put16(t + 18, p->urgptr);
    sum += 6 + 20;
    put16(t + 16, inet_csum(t, 20, sum));
    return ih + 20;
}

void xah_tcp(xprofile *p, const xah_pkt *k)
{
    ct_flow *f = k->f;
    const char *host;
    char cl[64];
    if (!f || !p->ahl || !f->ah_check || f->ah_final || !(host = f->chost))
        return;
    client_str(f, cl, sizeof(cl));
    if (k->reverse) {
        /* the server's first answers: a RST or a redirect away is a failure,
         * an answer past incoming-maxseq a success */
        uint32_t rseq = f->server.seq_last - f->server.seq0;
        int fail = 0;
        if (!p->ah_incoming_maxseq || !rseq)
            return;
        if (!seq_within(f->server.seq_last, f->server.seq0 + 1, f->server.seq0 + p->ah_incoming_maxseq)) {
            LOGD("autolist", "incoming rseq %u > %u", rseq, p->ah_incoming_maxseq);
            xah_reset(p, host, cl, f->l7proto);
            f->ah_final = 1;
            return;
        }
        if (k->p->tcpflags & 0x04) {
            LOGD("autolist", "incoming RST for %s rseq %u", host, rseq);
            debug("%s : profile %d (%s) : client %s : proto %s : rseq %u : incoming RST", host, p->n, pname(p), cl,
                  l7_proto_name(f->l7proto), rseq);
            fail = 1;
        } else if (k->len && k->l7p == L7P_HTTP_REPLY) {
            fail = l7_http_dpi_redirect(k->payload, k->len, host);
            LOGD("autolist", "HTTP reply for %s: %s", host, fail ? "a redirect to another domain" : "not a DPI redirect");
            if (fail)
                debug("%s : profile %d (%s) : client %s : proto %s : rseq %u : redirect to another domain", host,
                      p->n, pname(p), cl, l7_proto_name(f->l7proto), rseq);
        }
        if (fail) {
            xah_failed(p, host, f->chost_ip, cl, f->l7proto, k->now_ms);
            f->ah_final = 1;
        }
        return;
    }
    /* the client's data: retransmissions of the request */
    if ((k->p->tcpflags & 0x02) || !k->len || f->ah_retrans == XAH_RETRANS_STOP)
        return;
    if (f->state != CT_SYN) {
        if (!seq_within(f->client.seq_last, f->client.seq0, f->client.seq0 + p->ah_retrans_maxseq)) {
            LOGD("autolist", "retrans: seq %u past %u, stop", f->client.seq_last,
                 f->client.seq0 + p->ah_retrans_maxseq);
            f->ah_final = 1;
            f->ah_retrans = XAH_RETRANS_STOP;
            xah_reset(p, host, cl, f->l7proto);
            return;
        }
        if (!ct_is_retrans(&f->client))
            return;
    }
    if (++f->ah_retrans < p->ah_retrans_threshold) {
        LOGD("autolist", "retrans counter %u/%d", f->ah_retrans, p->ah_retrans_threshold);
        return;
    }
    LOGD("autolist", "retrans threshold reached %u/%d", f->ah_retrans, p->ah_retrans_threshold);
    f->ah_retrans = XAH_RETRANS_STOP;
    f->ah_final = 1;
    if (p->ah_retrans_reset && k->send) {
        uint8_t rst[60];
        size_t n = xah_rst(k->p, f, rst);
        if (n) {
            LOGD("autolist", "sending RST to the retransmitter");
            k->send(k->ud, rst, n);
        }
    }
    debug("%s : profile %d (%s) : client %s : proto %s : retrans threshold reached", host, p->n, pname(p), cl,
          l7_proto_name(f->l7proto));
    xah_failed(p, host, f->chost_ip, cl, f->l7proto, k->now_ms);
}

void xah_udp(xprofile *p, const xah_pkt *k)
{
    ct_flow *f = k->f;
    const char *host;
    char cl[64];
    if (!f || !p->ahl || !f->ah_check || f->ah_final || !p->ah_udp_out || !(host = f->chost))
        return;
    client_str(f, cl, sizeof(cl));
    if (f->server.pcounter > (uint64_t)p->ah_udp_in) {
        f->ah_final = 1;
        LOGD("autolist", "udp_in %llu > %d", (unsigned long long)f->server.pcounter, p->ah_udp_in);
        xah_reset(p, host, cl, f->l7proto);
    } else if (f->client.pcounter >= (uint64_t)p->ah_udp_out) {
        f->ah_final = 1;
        LOGD("autolist", "udp_in %llu <= %d, udp_out %llu >= %d", (unsigned long long)f->server.pcounter,
             p->ah_udp_in, (unsigned long long)f->client.pcounter, p->ah_udp_out);
        debug("%s : profile %d (%s) : client %s : proto %s : udp_in %llu<=%d udp_out %llu>=%d", host, p->n, pname(p),
              cl, l7_proto_name(f->l7proto), (unsigned long long)f->server.pcounter, p->ah_udp_in,
              (unsigned long long)f->client.pcounter, p->ah_udp_out);
        xah_failed(p, host, f->chost_ip, cl, f->l7proto, k->now_ms);
    }
}
