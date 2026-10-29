/* Packet parsing, building and description. Field access is in pkt_fields.c. */
#include "pkt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat.h"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* ---- values -------------------------------------------------------------- */

void gval_int(gval *v, int64_t i)
{
    v->is_str = 0;
    v->i = i;
    v->s = NULL;
}

void gval_strn(gval *v, const char *s, size_t n)
{
    v->is_str = 1;
    v->i = 0;
    v->s = xstrndup(s, n);
}

void gval_str(gval *v, const char *s) { gval_strn(v, s, strlen(s)); }

void gval_free(gval *v)
{
    free(v->s);
    v->s = NULL;
}

void gval_copy(gval *dst, const gval *src)
{
    *dst = *src;
    if (src->is_str && src->s)
        dst->s = xstrdup(src->s);
}

int gval_eq(const gval *a, const gval *b)
{
    if (a->is_str != b->is_str)
        return 0;
    if (a->is_str)
        return strcmp(a->s ? a->s : "", b->s ? b->s : "") == 0;
    return a->i == b->i;
}

void gval_print(sbuf *out, const gval *v)
{
    if (v->is_str)
        sb_puts(out, v->s ? v->s : "");
    else
        sb_printf(out, "%lld", (long long)v->i);
}

/* ---- checksums ----------------------------------------------------------- */

uint16_t inet_csum(const uint8_t *p, size_t n, uint32_t init)
{
    uint32_t sum = init;
    while (n > 1) {
        sum += (uint32_t)((p[0] << 8) | p[1]);
        p += 2;
        n -= 2;
    }
    if (n)
        sum += (uint32_t)(p[0] << 8);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint32_t sum_words(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2)
        s += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (n & 1)
        s += (uint32_t)(p[n - 1] << 8);
    return s;
}

static uint32_t pseudo_sum(const gpkt *p, uint8_t proto, size_t l4len)
{
    uint32_t s;
    if (p->ipver == 6) {
        s = sum_words(p->src, 16) + sum_words(p->dst, 16);
        s += (uint32_t)(l4len >> 16) + (uint32_t)(l4len & 0xffff);
        s += proto;
    } else {
        s = sum_words(p->src, 4) + sum_words(p->dst, 4);
        s += proto;
        s += (uint32_t)(l4len & 0xffff);
    }
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return s;
}

/* ---- flags --------------------------------------------------------------- */

static const char tcp_flag_letters[] = "FSRPAUECN";

void tcp_flags_str(uint16_t flags, char *out)
{
    int n = 0;
    for (int i = 0; i < 9; i++)
        if (flags & (1u << i))
            out[n++] = tcp_flag_letters[i];
    out[n] = 0;
}

int tcp_flags_parse(const char *s, uint16_t *out)
{
    uint16_t f = 0;
    int64_t v;
    if (parse_i64(s, &v) == 0) {
        if (v < 0 || v > 0x1ff)
            return -1;
        *out = (uint16_t)v;
        return 0;
    }
    for (; *s; s++) {
        const char *c = strchr(tcp_flag_letters, *s);
        if (!c || !*s)
            return -1;
        f |= (uint16_t)(1u << (c - tcp_flag_letters));
    }
    *out = f;
    return 0;
}

static const char *ip_flag_names[] = {"MF", "DF", "evil"};

void ip_flags_str(uint8_t flags, char *out)
{
    out[0] = 0;
    for (int i = 0; i < 3; i++) {
        if (flags & (1u << i)) {
            if (out[0])
                strcat(out, "+");
            strcat(out, ip_flag_names[i]);
        }
    }
}

int ip_flags_parse(const char *s, uint8_t *out)
{
    uint8_t f = 0;
    int64_t v;
    if (parse_i64(s, &v) == 0) {
        if (v < 0 || v > 7)
            return -1;
        *out = (uint8_t)v;
        return 0;
    }
    while (*s) {
        const char *end = strchr(s, '+');
        size_t n = end ? (size_t)(end - s) : strlen(s);
        int found = 0;
        for (int i = 0; i < 3; i++) {
            if (strlen(ip_flag_names[i]) == n && str_ieqn(s, ip_flag_names[i], n)) {
                f |= (uint8_t)(1u << i);
                found = 1;
            }
        }
        if (!found)
            return -1;
        s += n;
        if (*s == '+')
            s++;
    }
    *out = f;
    return 0;
}

/* ---- parsing ------------------------------------------------------------- */

static void set_payload_raw(gpkt *p, const uint8_t *d, size_t n)
{
    free(p->payload);
    p->payload = n ? xmalloc(n) : NULL;
    if (n)
        memcpy(p->payload, d, n);
    p->payload_len = n;
}

static void parse_tcp_options(gpkt *p, const uint8_t *o, size_t n)
{
    size_t i = 0;
    p->nopts = 0;
    while (i < n && p->nopts < TCP_MAX_OPTS) {
        uint8_t kind = o[i];
        tcp_opt *t = &p->opts[p->nopts];
        if (kind == 0 || kind == 1) {
            t->kind = kind;
            t->len = 0;
            p->nopts++;
            i++;
            if (kind == 0) {
                /* scapy stops at EOL; what follows is padding. */
                break;
            }
            continue;
        }
        if (i + 1 >= n || o[i + 1] < 2 || i + o[i + 1] > n || o[i + 1] - 2 > (int)sizeof(t->data))
            break;
        t->kind = kind;
        t->len = (uint8_t)(o[i + 1] - 2);
        memcpy(t->data, o + i + 2, t->len);
        p->nopts++;
        i += o[i + 1];
    }
    if (i < n) {
        /* Keep anything we could not parse (except EOL padding zeros). */
        size_t rest = n - i;
        int all_zero = 1;
        for (size_t k = i; k < n; k++)
            if (o[k])
                all_zero = 0;
        if (!all_zero) {
            p->opts_tail = xmalloc(rest);
            memcpy(p->opts_tail, o + i, rest);
            p->opts_tail_len = rest;
        }
    }
}

static void parse_l4(gpkt *p, uint8_t proto, const uint8_t *d, size_t n, int is_fragment)
{
    p->l4 = LAYER_NONE;
    if (!is_fragment && proto == 6 && n >= 20) {
        uint8_t dofs = d[12] >> 4;
        if (dofs >= 5 && (size_t)dofs * 4 <= n) {
            p->l4 = LAYER_TCP;
            p->sport = rd16(d);
            p->dport = rd16(d + 2);
            p->seq = rd32(d + 4);
            p->ack = rd32(d + 8);
            p->dataofs = dofs;
            p->reserved = (d[12] >> 1) & 7;
            p->tcpflags = (uint16_t)(((d[12] & 1) << 8) | d[13]);
            p->window = rd16(d + 14);
            p->l4sum = rd16(d + 16);
            p->urgptr = rd16(d + 18);
            parse_tcp_options(p, d + 20, (size_t)dofs * 4 - 20);
            set_payload_raw(p, d + dofs * 4, n - (size_t)dofs * 4);
            return;
        }
    }
    if (!is_fragment && proto == 17 && n >= 8) {
        size_t plen = n - 8;
        p->l4 = LAYER_UDP;
        p->sport = rd16(d);
        p->dport = rd16(d + 2);
        p->udplen = rd16(d + 4);
        p->l4sum = rd16(d + 6);
        /* like scapy, the UDP length trims trailing padding */
        if (p->udplen >= 8 && (size_t)p->udplen - 8 <= plen)
            plen = (size_t)p->udplen - 8;
        set_payload_raw(p, d + 8, plen);
        return;
    }
    set_payload_raw(p, d, n);
}

static int parse_v4(gpkt *p, const uint8_t *d, size_t len)
{
    size_t hl, end;
    uint16_t ff;
    if (len < 20)
        return -1;
    p->ipver = 4;
    p->version = d[0] >> 4;
    p->ihl = d[0] & 15;
    hl = (size_t)p->ihl * 4;
    if (p->ihl < 5 || hl > len)
        return -1;
    p->tos = d[1];
    p->iplen = rd16(d + 2);
    p->id = rd16(d + 4);
    ff = rd16(d + 6);
    p->ipflags = (uint8_t)(ff >> 13);
    p->frag = ff & 0x1fff;
    p->ttl = d[8];
    p->proto = d[9];
    p->l4proto = d[9];
    p->ipsum = rd16(d + 10);
    memcpy(p->src, d + 12, 4);
    memcpy(p->dst, d + 16, 4);
    p->ipopts_len = (uint8_t)(hl - 20);
    memcpy(p->ipopts, d + 20, hl - 20);
    end = (p->iplen >= hl && p->iplen <= len) ? p->iplen : len;
    parse_l4(p, p->proto, d + hl, end - hl, p->frag != 0);
    return 0;
}

static int parse_v6(gpkt *p, const uint8_t *d, size_t len)
{
    size_t end, off = 40;
    uint8_t nh;
    int is_fragment = 0;
    if (len < 40)
        return -1;
    p->ipver = 6;
    p->version = d[0] >> 4;
    p->tc = (uint8_t)(((d[0] & 15) << 4) | (d[1] >> 4));
    p->fl = ((uint32_t)(d[1] & 15) << 16) | ((uint32_t)d[2] << 8) | d[3];
    p->plen = rd16(d + 4);
    p->nh = d[6];
    p->hlim = d[7];
    memcpy(p->src, d + 8, 16);
    memcpy(p->dst, d + 24, 16);
    end = (p->plen && 40 + (size_t)p->plen <= len) ? 40 + (size_t)p->plen : len;
    nh = p->nh;
    /* walk extension headers */
    for (;;) {
        size_t hlen;
        if (nh == 0 || nh == 43 || nh == 60) {
            if (off + 8 > end)
                break;
            hlen = ((size_t)d[off + 1] + 1) * 8;
        } else if (nh == 51) {
            if (off + 8 > end)
                break;
            hlen = ((size_t)d[off + 1] + 2) * 4;
        } else if (nh == 44) {
            if (off + 8 > end)
                break;
            hlen = 8;
            if ((rd16(d + off + 2) >> 3) != 0)
                is_fragment = 1;
        } else {
            break;
        }
        if (off + hlen > end)
            break;
        nh = d[off];
        off += hlen;
        if (is_fragment)
            break;
    }
    if (off > 40) {
        p->ext_len = off - 40;
        p->ext = xmalloc(p->ext_len);
        memcpy(p->ext, d + 40, p->ext_len);
    }
    p->l4proto = nh;
    parse_l4(p, nh, d + off, end - off, is_fragment);
    return 0;
}

gpkt *pkt_parse(const uint8_t *data, size_t len)
{
    gpkt *p;
    int rc;
    if (len == 0 || len > PKT_MAX)
        return NULL;
    p = xcalloc(1, sizeof(*p));
    if ((data[0] >> 4) == 4)
        rc = parse_v4(p, data, len);
    else if ((data[0] >> 4) == 6)
        rc = parse_v6(p, data, len);
    else
        rc = -1;
    if (rc < 0) {
        pkt_free(p);
        return NULL;
    }
    p->raw = xmalloc(len);
    memcpy(p->raw, data, len);
    p->raw_len = len;
    return p;
}

gpkt *pkt_copy(const gpkt *src)
{
    gpkt *p = xmalloc(sizeof(*p));
    *p = *src;
    p->payload = NULL;
    p->raw = NULL;
    p->ext = NULL;
    p->opts_tail = NULL;
    if (src->payload_len) {
        p->payload = xmalloc(src->payload_len);
        memcpy(p->payload, src->payload, src->payload_len);
    }
    if (src->raw_len) {
        p->raw = xmalloc(src->raw_len);
        memcpy(p->raw, src->raw, src->raw_len);
    }
    if (src->ext_len) {
        p->ext = xmalloc(src->ext_len);
        memcpy(p->ext, src->ext, src->ext_len);
    }
    if (src->opts_tail_len) {
        p->opts_tail = xmalloc(src->opts_tail_len);
        memcpy(p->opts_tail, src->opts_tail, src->opts_tail_len);
    }
    return p;
}

void pkt_free(gpkt *p)
{
    if (!p)
        return;
    free(p->payload);
    free(p->raw);
    free(p->ext);
    free(p->opts_tail);
    free(p);
}

void pkt_mark_dirty(gpkt *p)
{
    p->dirty = 1;
    free(p->raw);
    p->raw = NULL;
    p->raw_len = 0;
}

void pkt_set_payload(gpkt *p, const uint8_t *data, size_t len)
{
    set_payload_raw(p, data, len);
    pkt_mark_dirty(p);
}

/* ---- building ------------------------------------------------------------ */

static size_t opt_wire_len(const tcp_opt *o) { return (o->kind <= 1) ? 1 : (size_t)o->len + 2; }

static size_t build_tcp_opts(const gpkt *p, uint8_t *out)
{
    size_t n = 0;
    for (int i = 0; i < p->nopts; i++) {
        const tcp_opt *o = &p->opts[i];
        size_t w = opt_wire_len(o);
        if (n + w > 40)
            break;
        out[n] = o->kind;
        if (o->kind > 1) {
            out[n + 1] = (uint8_t)(o->len + 2);
            memcpy(out + n + 2, o->data, o->len);
        }
        n += w;
    }
    if (p->opts_tail_len && n + p->opts_tail_len <= 40) {
        memcpy(out + n, p->opts_tail, p->opts_tail_len);
        n += p->opts_tail_len;
    }
    while (n % 4)
        out[n++] = 0;
    return n;
}

/* Builds the L4 header+payload at out; returns its length. */
static size_t build_l4(gpkt *p, uint8_t *out, size_t cap)
{
    if (p->l4 == LAYER_TCP) {
        uint8_t opts[44];
        size_t ol = build_tcp_opts(p, opts);
        size_t hl = 20 + ol;
        size_t total = hl + p->payload_len;
        uint8_t dofs;
        if (total > cap)
            return 0;
        if (p->auto_fields & AUTO_TCP_DOFS)
            p->dataofs = (uint8_t)(hl / 4);
        dofs = p->dataofs;
        wr16(out, p->sport);
        wr16(out + 2, p->dport);
        wr32(out + 4, p->seq);
        wr32(out + 8, p->ack);
        out[12] = (uint8_t)(((dofs & 15) << 4) | ((p->reserved & 7) << 1) | ((p->tcpflags >> 8) & 1));
        out[13] = (uint8_t)p->tcpflags;
        wr16(out + 14, p->window);
        wr16(out + 16, 0);
        wr16(out + 18, p->urgptr);
        memcpy(out + 20, opts, ol);
        if (p->payload_len)
            memcpy(out + hl, p->payload, p->payload_len);
        if (p->auto_fields & AUTO_TCP_CSUM)
            p->l4sum = inet_csum(out, total, pseudo_sum(p, 6, total));
        wr16(out + 16, p->l4sum);
        return total;
    }
    if (p->l4 == LAYER_UDP) {
        size_t total = 8 + p->payload_len;
        if (total > cap)
            return 0;
        if (p->auto_fields & AUTO_UDP_LEN)
            p->udplen = (uint16_t)total;
        wr16(out, p->sport);
        wr16(out + 2, p->dport);
        wr16(out + 4, p->udplen);
        wr16(out + 6, 0);
        if (p->payload_len)
            memcpy(out + 8, p->payload, p->payload_len);
        if (p->auto_fields & AUTO_UDP_CSUM) {
            uint16_t s = inet_csum(out, total, pseudo_sum(p, 17, total));
            p->l4sum = s ? s : 0xffff;
        }
        wr16(out + 6, p->l4sum);
        return total;
    }
    if (p->payload_len > cap)
        return 0;
    if (p->payload_len)
        memcpy(out, p->payload, p->payload_len);
    return p->payload_len;
}

size_t pkt_build(gpkt *p, uint8_t *out, size_t cap)
{
    size_t hl, l4len, total;
    if (!p->dirty && p->raw) {
        if (p->raw_len > cap)
            return 0;
        memcpy(out, p->raw, p->raw_len);
        return p->raw_len;
    }
    if (p->ipver == 6) {
        hl = 40 + p->ext_len;
        if (hl > cap)
            return 0;
        l4len = build_l4(p, out + hl, cap - hl);
        if (l4len == 0 && (p->l4 != LAYER_NONE || p->payload_len))
            return 0;
        total = hl + l4len;
        if (p->auto_fields & AUTO_V6_PLEN)
            p->plen = (uint16_t)(total - 40);
        out[0] = (uint8_t)((p->version << 4) | (p->tc >> 4));
        out[1] = (uint8_t)(((p->tc & 15) << 4) | ((p->fl >> 16) & 15));
        out[2] = (uint8_t)(p->fl >> 8);
        out[3] = (uint8_t)p->fl;
        wr16(out + 4, p->plen);
        out[6] = p->nh;
        out[7] = p->hlim;
        memcpy(out + 8, p->src, 16);
        memcpy(out + 24, p->dst, 16);
        if (p->ext_len)
            memcpy(out + 40, p->ext, p->ext_len);
        return total;
    }
    hl = 20 + p->ipopts_len;
    if (hl > cap)
        return 0;
    l4len = build_l4(p, out + hl, cap - hl);
    if (l4len == 0 && (p->l4 != LAYER_NONE || p->payload_len))
        return 0;
    total = hl + l4len;
    if (p->auto_fields & AUTO_IP_LEN)
        p->iplen = (uint16_t)total;
    if (p->auto_fields & AUTO_IP_IHL)
        p->ihl = (uint8_t)(hl / 4);
    out[0] = (uint8_t)((p->version << 4) | (p->ihl & 15));
    out[1] = p->tos;
    wr16(out + 2, p->iplen);
    wr16(out + 4, p->id);
    wr16(out + 6, (uint16_t)(((p->ipflags & 7) << 13) | (p->frag & 0x1fff)));
    out[8] = p->ttl;
    out[9] = p->proto;
    wr16(out + 10, 0);
    memcpy(out + 12, p->src, 4);
    memcpy(out + 16, p->dst, 4);
    memcpy(out + 20, p->ipopts, p->ipopts_len);
    if (p->auto_fields & AUTO_IP_CSUM)
        p->ipsum = inet_csum(out, hl, 0);
    wr16(out + 10, p->ipsum);
    return total;
}

uint8_t *pkt_bytes(gpkt *p, size_t *len)
{
    uint8_t *buf = xmalloc(PKT_MAX + 64);
    *len = pkt_build(p, buf, PKT_MAX + 64);
    return buf;
}

/* ---- description --------------------------------------------------------- */

static void addr_str(const gpkt *p, const uint8_t *a, char *out, size_t n)
{
    inet_ntop(p->ipver == 6 ? AF_INET6 : AF_INET, a, out, (socklen_t)n);
}

void pkt_describe(const gpkt *p, sbuf *out)
{
    char s[64], d[64], fl[16];
    size_t show = MIN(p->payload_len, (size_t)48);
    addr_str(p, p->src, s, sizeof(s));
    addr_str(p, p->dst, d, sizeof(d));
    if (p->l4 == LAYER_TCP) {
        tcp_flags_str(p->tcpflags, fl);
        sb_printf(out, "TCP %s:%u --> %s:%u [%s] seq=%u ack=%u len=%zu", s, p->sport, d, p->dport,
                  fl, p->seq, p->ack, p->payload_len);
    } else if (p->l4 == LAYER_UDP) {
        sb_printf(out, "UDP %s:%u --> %s:%u len=%zu", s, p->sport, d, p->dport, p->payload_len);
    } else {
        sb_printf(out, "IP%s %s --> %s proto=%u frag=%u len=%zu", p->ipver == 6 ? "v6" : "", s,
                  d, p->l4proto, p->frag, p->payload_len);
    }
    if (p->ipver == 4)
        sb_printf(out, " ttl=%u", p->ttl);
    else
        sb_printf(out, " hlim=%u", p->hlim);
    if (show) {
        sb_puts(out, " ");
        for (size_t i = 0; i < show; i++) {
            uint8_t c = p->payload[i];
            if (c >= 0x20 && c < 0x7f && c != '\\')
                sb_putc(out, (char)c);
            else
                sb_printf(out, "\\x%02x", c);
        }
        if (show < p->payload_len)
            sb_puts(out, "...");
    }
}
