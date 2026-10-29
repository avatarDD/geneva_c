/*
 * Field access by Geneva names: get / set / gen / parse, plus field
 * restrictions used by the genetic algorithm (--protos, --fields,
 * --disable-fields).
 */
#include "pkt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plat.h"
#include "rng.h"

/* ---- layer tables -------------------------------------------------------- */

static const char *const ip_fields[] = {"version", "ihl", "tos", "len", "id", "flags", "frag",
                                        "ttl", "proto", "chksum", "src", "dst", "load", NULL};
static const char *const tcp_fields[] = {
    "sport", "dport", "seq", "ack", "dataofs", "reserved", "flags", "window", "chksum", "urgptr",
    "load", "options-eol", "options-nop", "options-mss", "options-wscale", "options-sackok",
    "options-sack", "options-timestamp", "options-altchksum", "options-altchksumopt",
    "options-md5header", "options-uto", NULL};
static const char *const udp_fields[] = {"sport", "dport", "chksum", "len", "load", NULL};
static const char *const dns_fields[] = {"id", "qr", "opcode", "aa", "tc", "rd", "ra", "z", "ad",
                                         "cd", "qd", "rcode", "qdcount", "ancount", "nscount",
                                         "arcount", NULL};
static const char *const dnsqr_fields[] = {"qname", "qtype", "qclass", NULL};
static const char *const ipv6_fields[] = {"version", "tc", "fl", "plen", "nh", "hlim", "src", "dst",
                                          "load", NULL};

static const char *const *const all_fields[LAYER_COUNT] = {
    ip_fields, tcp_fields, udp_fields, dns_fields, dnsqr_fields, ipv6_fields,
};
static const char *const layer_names[LAYER_COUNT] = {"IP", "TCP", "UDP", "DNS", "DNSQR", "IPv6"};

layer_id layer_by_name(const char *name)
{
    for (int i = 0; i < LAYER_COUNT; i++)
        if (str_ieq(name, layer_names[i]))
            return (layer_id)i;
    if (str_ieq(name, "DNS Question Record"))
        return LAYER_DNSQR;
    if (str_ieq(name, "IP6"))
        return LAYER_IPV6;
    return LAYER_NONE;
}

const char *layer_name(layer_id id)
{
    return (id >= 0 && id < LAYER_COUNT) ? layer_names[id] : "?";
}

const char *const *layer_fields(layer_id id)
{
    return (id >= 0 && id < LAYER_COUNT) ? all_fields[id] : NULL;
}

int layer_has_field(layer_id id, const char *field)
{
    const char *const *f = layer_fields(id);
    if (!f)
        return 0;
    for (; *f; f++)
        if (strcmp(*f, field) == 0)
            return 1;
    return 0;
}

/* ---- DNS helpers --------------------------------------------------------- */

static int dns_present(const gpkt *p)
{
    if (p->l4 != LAYER_UDP || p->payload_len < 12)
        return 0;
    return p->sport == 53 || p->dport == 53 || p->sport == 5353 || p->dport == 5353;
}

/* Decodes a DNS name at off; returns the offset just past it (in the
 * uncompressed stream) or 0 on error. */
static size_t dns_read_name(const uint8_t *m, size_t mlen, size_t off, sbuf *out)
{
    size_t end = 0, jumps = 0;
    while (off < mlen) {
        uint8_t l = m[off];
        if (l == 0) {
            if (!end)
                end = off + 1;
            if (out && out->len == 0)
                sb_putc(out, '.');
            return end;
        }
        if ((l & 0xC0) == 0xC0) {
            if (off + 1 >= mlen || ++jumps > 16)
                return 0;
            if (!end)
                end = off + 2;
            off = (size_t)((l & 0x3F) << 8 | m[off + 1]);
            continue;
        }
        if (l & 0xC0 || off + 1 + l > mlen)
            return 0;
        if (out) {
            sb_append(out, m + off + 1, l);
            sb_putc(out, '.');
        }
        off += 1 + (size_t)l;
    }
    return 0;
}

static int dnsqr_present(const gpkt *p, size_t *name_end)
{
    size_t e;
    if (!dns_present(p))
        return 0;
    if (((p->payload[4] << 8) | p->payload[5]) == 0)
        return 0;
    e = dns_read_name(p->payload, p->payload_len, 12, NULL);
    if (!e || e + 4 > p->payload_len)
        return 0;
    if (name_end)
        *name_end = e;
    return 1;
}

static void dns_encode_name(sbuf *out, const char *name)
{
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.');
        size_t n = dot ? (size_t)(dot - s) : strlen(s);
        if (n > 63)
            n = 63;
        if (n) {
            uint8_t l = (uint8_t)n;
            sb_append(out, &l, 1);
            sb_append(out, s, n);
        }
        if (!dot)
            break;
        s = dot + 1;
    }
    sb_putc(out, 0);
}

int pkt_has_layer(const gpkt *p, layer_id id)
{
    switch (id) {
    case LAYER_IP:
        /* IPv4 field names also apply to IPv6 packets where an equivalent
         * exists (ttl -> hlim, tos -> tc, proto -> nh); see field_alias(). */
        return p->ipver == 4 || p->ipver == 6;
    case LAYER_IPV6:
        return p->ipver == 6;
    case LAYER_TCP:
        return p->l4 == LAYER_TCP;
    case LAYER_UDP:
        return p->l4 == LAYER_UDP;
    case LAYER_DNS:
        return dns_present(p);
    case LAYER_DNSQR:
        return dnsqr_present(p, NULL);
    default:
        return 0;
    }
}

/* ---- TCP options --------------------------------------------------------- */

static const struct {
    const char *name;
    uint8_t kind;
    int is_int;   /* value is an integer (mss, wscale, ...) */
    int int_size; /* bytes of the integer on the wire */
    int extra;    /* zero bytes appended after the integer */
    int gen_len;  /* random bytes generated for byte-valued options */
} tcp_opt_table[] = {
    {"eol", 0, 0, 0, 0, 0},       {"nop", 1, 0, 0, 0, 0},       {"mss", 2, 1, 2, 0, 0},
    {"wscale", 3, 1, 1, 0, 0},    {"sackok", 4, 0, 0, 0, 0},    {"sack", 5, 0, 0, 0, 0},
    {"timestamp", 8, 1, 4, 4, 0}, {"altchksum", 14, 1, 1, 2, 0}, {"altchksumopt", 15, 0, 0, 0, 0},
    {"md5header", 19, 0, 0, 0, 16}, {"uto", 28, 1, 2, 0, 0},
};

static int opt_index(const char *field)
{
    if (!str_starts(field, "options-"))
        return -1;
    for (int i = 0; i < (int)ARRAY_LEN(tcp_opt_table); i++)
        if (str_ieq(field + 8, tcp_opt_table[i].name))
            return i;
    return -1;
}

static uint64_t be_int(const uint8_t *d, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n && i < 8; i++)
        v = (v << 8) | d[i];
    return v;
}

static int get_option(const gpkt *p, int oi, gval *out)
{
    uint8_t kind = tcp_opt_table[oi].kind;
    for (int i = 0; i < p->nopts; i++) {
        const tcp_opt *o = &p->opts[i];
        if (o->kind != kind)
            continue;
        if (kind <= 1 || kind == 4) {
            gval_str(out, "");
        } else if (kind == 5) {
            if (o->len >= 4)
                gval_int(out, (int64_t)be_int(o->data, 4));
            else
                gval_str(out, "");
        } else if (tcp_opt_table[oi].is_int) {
            if (o->len >= tcp_opt_table[oi].int_size)
                gval_int(out, (int64_t)be_int(o->data, (size_t)tcp_opt_table[oi].int_size));
            else
                gval_str(out, "");
        } else {
            sbuf b;
            sb_init(&b);
            hex_encode(&b, o->data, o->len);
            out->is_str = 1;
            out->i = 0;
            out->s = sb_take(&b);
        }
        return 0;
    }
    gval_str(out, "");
    return 0;
}

static int set_option(gpkt *p, int oi, const gval *v)
{
    tcp_opt o;
    uint8_t bytes[64];
    long blen = 0;
    int is_bytes = 0;
    uint64_t iv = 0;
    memset(&o, 0, sizeof(o));
    o.kind = tcp_opt_table[oi].kind;
    if (v->is_str) {
        blen = hex_decode(v->s ? v->s : "", bytes, sizeof(bytes));
        if (blen < 0)
            return -1;
        is_bytes = 1;
    } else {
        iv = (uint64_t)v->i;
    }
    if (o.kind <= 1 || o.kind == 4 || o.kind == 5) {
        o.len = 0;
    } else if (tcp_opt_table[oi].is_int) {
        int sz = tcp_opt_table[oi].int_size;
        if (is_bytes)
            iv = be_int(bytes, (size_t)blen);
        for (int i = 0; i < sz; i++)
            o.data[i] = (uint8_t)(iv >> (8 * (sz - 1 - i)));
        o.len = (uint8_t)(sz + tcp_opt_table[oi].extra);
    } else {
        if (!is_bytes) {
            /* an integer for a byte-valued option: encode big-endian */
            int n = 0;
            uint64_t t = iv;
            do {
                n++;
                t >>= 8;
            } while (t);
            for (int i = 0; i < n; i++)
                bytes[i] = (uint8_t)(iv >> (8 * (n - 1 - i)));
            blen = n;
        }
        if ((size_t)blen > sizeof(o.data))
            blen = sizeof(o.data);
        memcpy(o.data, bytes, (size_t)blen);
        o.len = (uint8_t)blen;
    }
    for (int i = 0; i < p->nopts; i++) {
        if (p->opts[i].kind == o.kind) {
            p->opts[i] = o;
            goto done;
        }
    }
    if (p->nopts >= TCP_MAX_OPTS)
        return -1;
    p->opts[p->nopts++] = o;
done:
    p->auto_fields |= AUTO_TCP_DOFS | AUTO_IP_LEN | AUTO_V6_PLEN;
    return 0;
}

/* ---- load ---------------------------------------------------------------- */

static void get_load(const gpkt *p, gval *out)
{
    sbuf b;
    /* scapy parses port-53 UDP payloads as DNS, which has no "load" */
    if (dns_present(p) || !p->payload_len) {
        gval_str(out, "");
        return;
    }
    sb_init(&b);
    url_quote(&b, p->payload, p->payload_len);
    out->is_str = 1;
    out->i = 0;
    out->s = sb_take(&b);
}

static const uint8_t dns_payload[] =
    "\x00\x39\x69\x62\x81\x80\x00\x01\x00\x01\x00\x00\x00\x01\x08\x66\x61\x63\x65\x66\x61\x63\x65"
    "\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2b\x00\x04\xc7\xbf"
    "\x32\x49\x00\x00\x29\x02\x00\x00\x00\x00\x00\x00\x00";
static const char http_payload[] = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";

static void replace_all(sbuf *b, const char *needle, const uint8_t *rep, size_t replen)
{
    size_t nl = strlen(needle);
    sbuf out;
    size_t i = 0;
    if (b->len < nl)
        return;
    sb_init(&out);
    while (i < b->len) {
        if (i + nl <= b->len && memcmp(b->data + i, needle, nl) == 0) {
            sb_append(&out, rep, replen);
            i += nl;
        } else {
            sb_append(&out, b->data + i, 1);
            i++;
        }
    }
    sb_free(b);
    *b = out;
}

/* Decodes a strategy load value: url-unquote plus Geneva's placeholders. */
static void decode_load(const gval *v, sbuf *out)
{
    sb_init(out);
    if (v->is_str) {
        const char *s = v->s ? v->s : "";
        sb_reserve(out, strlen(s));
        out->len = url_unquote(s, (uint8_t *)out->data);
        out->data[out->len] = 0;
    } else {
        sb_printf(out, "%lld", (long long)v->i);
    }
    replace_all(out, "__DNS_REQUEST__", dns_payload, sizeof(dns_payload) - 1);
    replace_all(out, "__HTTP_REQUEST__", (const uint8_t *)http_payload, sizeof(http_payload) - 1);
}

/* ---- helpers ------------------------------------------------------------- */

static int computed(gpkt *p, unsigned flag)
{
    /* Auto fields are only known after building; build into scratch. */
    if (p->auto_fields & flag) {
        uint8_t *tmp = xmalloc(PKT_MAX + 64);
        pkt_build(p, tmp, PKT_MAX + 64);
        free(tmp);
    }
    return 0;
}

static void addr_val(const gpkt *p, const uint8_t *a, gval *out)
{
    char buf[64];
    inet_ntop(p->ipver == 6 ? AF_INET6 : AF_INET, a, buf, sizeof(buf));
    gval_str(out, buf);
}

static int addr_set(gpkt *p, uint8_t *a, const gval *v)
{
    if (!v->is_str) {
        if (p->ipver != 4)
            return -1;
        a[0] = (uint8_t)(v->i >> 24);
        a[1] = (uint8_t)(v->i >> 16);
        a[2] = (uint8_t)(v->i >> 8);
        a[3] = (uint8_t)v->i;
        return 0;
    }
    return inet_pton(p->ipver == 6 ? AF_INET6 : AF_INET, v->s, a) == 1 ? 0 : -1;
}

/* Maps IPv4 field names onto IPv6 packets. Returns NULL if no equivalent. */
static const char *field_alias(const gpkt *p, layer_id layer, const char *field, layer_id *real)
{
    *real = layer;
    if (layer != LAYER_IP || p->ipver != 6)
        return field;
    *real = LAYER_IPV6;
    if (strcmp(field, "ttl") == 0)
        return "hlim";
    if (strcmp(field, "tos") == 0)
        return "tc";
    if (strcmp(field, "proto") == 0)
        return "nh";
    if (strcmp(field, "version") == 0 || strcmp(field, "src") == 0 ||
        strcmp(field, "dst") == 0 || strcmp(field, "load") == 0)
        return field;
    return NULL;
}

/* ---- get ----------------------------------------------------------------- */

int pkt_get(const gpkt *cp, layer_id layer, const char *field, gval *out)
{
    gpkt *p = (gpkt *)cp; /* computing auto fields caches them; logically const */
    char buf[32];
    layer_id real;
    gval_int(out, 0);
    if (!pkt_has_layer(p, layer))
        return -1;
    field = field_alias(p, layer, field, &real);
    if (!field || !layer_has_field(real, field))
        return -1;
    layer = real;

    if (strcmp(field, "load") == 0) {
        get_load(p, out);
        return 0;
    }
    switch (layer) {
    case LAYER_IP:
        if (!strcmp(field, "version")) gval_int(out, p->version);
        else if (!strcmp(field, "ihl")) { computed(p, AUTO_IP_IHL); gval_int(out, p->ihl); }
        else if (!strcmp(field, "tos")) gval_int(out, p->tos);
        else if (!strcmp(field, "len")) { computed(p, AUTO_IP_LEN); gval_int(out, p->iplen); }
        else if (!strcmp(field, "id")) gval_int(out, p->id);
        else if (!strcmp(field, "flags")) { ip_flags_str(p->ipflags, buf); gval_str(out, buf); }
        else if (!strcmp(field, "frag")) gval_int(out, p->frag);
        else if (!strcmp(field, "ttl")) gval_int(out, p->ttl);
        else if (!strcmp(field, "proto")) gval_int(out, p->proto);
        else if (!strcmp(field, "chksum")) { computed(p, AUTO_IP_CSUM); gval_int(out, p->ipsum); }
        else if (!strcmp(field, "src")) addr_val(p, p->src, out);
        else if (!strcmp(field, "dst")) addr_val(p, p->dst, out);
        else return -1;
        return 0;
    case LAYER_IPV6:
        if (!strcmp(field, "version")) gval_int(out, p->version);
        else if (!strcmp(field, "tc")) gval_int(out, p->tc);
        else if (!strcmp(field, "fl")) gval_int(out, p->fl);
        else if (!strcmp(field, "plen")) { computed(p, AUTO_V6_PLEN); gval_int(out, p->plen); }
        else if (!strcmp(field, "nh")) gval_int(out, p->nh);
        else if (!strcmp(field, "hlim")) gval_int(out, p->hlim);
        else if (!strcmp(field, "src")) addr_val(p, p->src, out);
        else if (!strcmp(field, "dst")) addr_val(p, p->dst, out);
        else return -1;
        return 0;
    case LAYER_TCP: {
        int oi = opt_index(field);
        if (oi >= 0)
            return get_option(p, oi, out);
        if (!strcmp(field, "sport")) gval_int(out, p->sport);
        else if (!strcmp(field, "dport")) gval_int(out, p->dport);
        else if (!strcmp(field, "seq")) gval_int(out, p->seq);
        else if (!strcmp(field, "ack")) gval_int(out, p->ack);
        else if (!strcmp(field, "dataofs")) { computed(p, AUTO_TCP_DOFS); gval_int(out, p->dataofs); }
        else if (!strcmp(field, "reserved")) gval_int(out, p->reserved);
        else if (!strcmp(field, "flags")) { tcp_flags_str(p->tcpflags, buf); gval_str(out, buf); }
        else if (!strcmp(field, "window")) gval_int(out, p->window);
        else if (!strcmp(field, "chksum")) { computed(p, AUTO_TCP_CSUM); gval_int(out, p->l4sum); }
        else if (!strcmp(field, "urgptr")) gval_int(out, p->urgptr);
        else return -1;
        return 0;
    }
    case LAYER_UDP:
        if (!strcmp(field, "sport")) gval_int(out, p->sport);
        else if (!strcmp(field, "dport")) gval_int(out, p->dport);
        else if (!strcmp(field, "len")) { computed(p, AUTO_UDP_LEN); gval_int(out, p->udplen); }
        else if (!strcmp(field, "chksum")) { computed(p, AUTO_UDP_CSUM); gval_int(out, p->l4sum); }
        else return -1;
        return 0;
    case LAYER_DNS: {
        const uint8_t *d = p->payload;
        uint16_t fl = (uint16_t)((d[2] << 8) | d[3]);
        if (!strcmp(field, "id")) gval_int(out, (d[0] << 8) | d[1]);
        else if (!strcmp(field, "qr")) gval_int(out, (fl >> 15) & 1);
        else if (!strcmp(field, "opcode")) gval_int(out, (fl >> 11) & 15);
        else if (!strcmp(field, "aa")) gval_int(out, (fl >> 10) & 1);
        else if (!strcmp(field, "tc")) gval_int(out, (fl >> 9) & 1);
        else if (!strcmp(field, "rd")) gval_int(out, (fl >> 8) & 1);
        else if (!strcmp(field, "ra")) gval_int(out, (fl >> 7) & 1);
        else if (!strcmp(field, "z")) gval_int(out, (fl >> 6) & 1);
        else if (!strcmp(field, "ad")) gval_int(out, (fl >> 5) & 1);
        else if (!strcmp(field, "cd")) gval_int(out, (fl >> 4) & 1);
        else if (!strcmp(field, "rcode")) gval_int(out, fl & 15);
        else if (!strcmp(field, "qdcount")) gval_int(out, (d[4] << 8) | d[5]);
        else if (!strcmp(field, "ancount")) gval_int(out, (d[6] << 8) | d[7]);
        else if (!strcmp(field, "nscount")) gval_int(out, (d[8] << 8) | d[9]);
        else if (!strcmp(field, "arcount")) gval_int(out, (d[10] << 8) | d[11]);
        else if (!strcmp(field, "qd")) {
            sbuf b;
            sb_init(&b);
            if (!dns_read_name(d, p->payload_len, 12, &b) || ((d[4] << 8) | d[5]) == 0)
                sb_reset(&b);
            out->is_str = 1;
            out->s = sb_take(&b);
        } else return -1;
        return 0;
    }
    case LAYER_DNSQR: {
        size_t e;
        dnsqr_present(p, &e);
        if (!strcmp(field, "qname")) {
            sbuf b;
            sb_init(&b);
            dns_read_name(p->payload, p->payload_len, 12, &b);
            out->is_str = 1;
            out->s = sb_take(&b);
        } else if (!strcmp(field, "qtype")) {
            gval_int(out, (p->payload[e] << 8) | p->payload[e + 1]);
        } else if (!strcmp(field, "qclass")) {
            gval_int(out, (p->payload[e + 2] << 8) | p->payload[e + 3]);
        } else {
            return -1;
        }
        return 0;
    }
    default:
        return -1;
    }
}

/* ---- set ----------------------------------------------------------------- */

static int want_int(const gval *v, int64_t *out)
{
    if (!v->is_str) {
        *out = v->i;
        return 0;
    }
    return parse_i64(v->s ? v->s : "", out);
}

static void dns_set16(gpkt *p, size_t off, uint16_t v)
{
    p->payload[off] = (uint8_t)(v >> 8);
    p->payload[off + 1] = (uint8_t)v;
}

static int set_dns_bit(gpkt *p, int shift, int bits, int64_t v)
{
    uint16_t fl = (uint16_t)((p->payload[2] << 8) | p->payload[3]);
    uint16_t mask = (uint16_t)(((1u << bits) - 1) << shift);
    fl = (uint16_t)((fl & ~mask) | (((uint16_t)v << shift) & mask));
    dns_set16(p, 2, fl);
    return 0;
}

static int set_qname(gpkt *p, const char *name)
{
    size_t e;
    sbuf b;
    if (!dnsqr_present(p, &e))
        return -1;
    /* end of the name itself (before qtype/qclass) */
    sb_init(&b);
    sb_append(&b, p->payload, 12);
    dns_encode_name(&b, name);
    sb_append(&b, p->payload + e, p->payload_len - e);
    pkt_set_payload(p, (const uint8_t *)b.data, b.len);
    sb_free(&b);
    p->auto_fields |= AUTO_IP_LEN | AUTO_V6_PLEN | AUTO_UDP_LEN;
    return 0;
}

int pkt_set(gpkt *p, layer_id layer, const char *field, const gval *v)
{
    int64_t iv = 0;
    layer_id real;
    if (!pkt_has_layer(p, layer))
        return -1;
    field = field_alias(p, layer, field, &real);
    if (!field || !layer_has_field(real, field))
        return -1;
    layer = real;

    /* Geneva's Packet.set() always lets scapy recompute the IP and TCP
     * checksums; UDP is recomputed too (scapy kept a stale one, a bug). */
    pkt_mark_dirty(p);
    p->auto_fields |= AUTO_IP_CSUM | AUTO_TCP_CSUM | AUTO_UDP_CSUM;

    if (strcmp(field, "load") == 0) {
        sbuf b;
        decode_load(v, &b);
        if (layer == LAYER_IP || layer == LAYER_IPV6)
            p->l4 = LAYER_NONE; /* IP:load replaces everything above IP */
        pkt_set_payload(p, (const uint8_t *)b.data, b.len);
        sb_free(&b);
        p->auto_fields |= AUTO_IP_LEN | AUTO_V6_PLEN | AUTO_UDP_LEN;
        return 0;
    }

    switch (layer) {
    case LAYER_IP:
        if (!strcmp(field, "flags")) {
            uint8_t f;
            if (v->is_str) {
                if (ip_flags_parse(v->s, &f) < 0)
                    return -1;
            } else {
                f = (uint8_t)(v->i & 7);
            }
            p->ipflags = f;
            return 0;
        }
        if (!strcmp(field, "src"))
            return addr_set(p, p->src, v);
        if (!strcmp(field, "dst"))
            return addr_set(p, p->dst, v);
        if (want_int(v, &iv) < 0)
            return -1;
        if (!strcmp(field, "version")) p->version = (uint8_t)(iv & 15);
        else if (!strcmp(field, "ihl")) { p->ihl = (uint8_t)(iv & 15); p->auto_fields &= ~(unsigned)AUTO_IP_IHL; }
        else if (!strcmp(field, "tos")) p->tos = (uint8_t)iv;
        else if (!strcmp(field, "len")) { p->iplen = (uint16_t)iv; p->auto_fields &= ~(unsigned)AUTO_IP_LEN; }
        else if (!strcmp(field, "id")) p->id = (uint16_t)iv;
        else if (!strcmp(field, "frag")) p->frag = (uint16_t)(iv & 0x1fff);
        else if (!strcmp(field, "ttl")) p->ttl = (uint8_t)iv;
        else if (!strcmp(field, "proto")) p->proto = (uint8_t)iv;
        else if (!strcmp(field, "chksum")) { p->ipsum = (uint16_t)iv; p->auto_fields &= ~(unsigned)AUTO_IP_CSUM; }
        else return -1;
        return 0;
    case LAYER_IPV6:
        if (!strcmp(field, "src"))
            return addr_set(p, p->src, v);
        if (!strcmp(field, "dst"))
            return addr_set(p, p->dst, v);
        if (want_int(v, &iv) < 0)
            return -1;
        if (!strcmp(field, "version")) p->version = (uint8_t)(iv & 15);
        else if (!strcmp(field, "tc")) p->tc = (uint8_t)iv;
        else if (!strcmp(field, "fl")) p->fl = (uint32_t)iv & 0xfffff;
        else if (!strcmp(field, "plen")) { p->plen = (uint16_t)iv; p->auto_fields &= ~(unsigned)AUTO_V6_PLEN; }
        else if (!strcmp(field, "nh")) p->nh = (uint8_t)iv;
        else if (!strcmp(field, "hlim")) p->hlim = (uint8_t)iv;
        else return -1;
        return 0;
    case LAYER_TCP: {
        int oi = opt_index(field);
        if (oi >= 0)
            return set_option(p, oi, v);
        if (!strcmp(field, "flags")) {
            uint16_t f;
            if (v->is_str) {
                if (tcp_flags_parse(v->s, &f) < 0)
                    return -1;
            } else {
                f = (uint16_t)(v->i & 0x1ff);
            }
            p->tcpflags = f;
            return 0;
        }
        if (want_int(v, &iv) < 0)
            return -1;
        if (!strcmp(field, "sport")) p->sport = (uint16_t)iv;
        else if (!strcmp(field, "dport")) p->dport = (uint16_t)iv;
        else if (!strcmp(field, "seq")) p->seq = (uint32_t)iv;
        else if (!strcmp(field, "ack")) p->ack = (uint32_t)iv;
        else if (!strcmp(field, "dataofs")) { p->dataofs = (uint8_t)(iv & 15); p->auto_fields &= ~(unsigned)AUTO_TCP_DOFS; }
        else if (!strcmp(field, "reserved")) p->reserved = (uint8_t)(iv & 7);
        else if (!strcmp(field, "window")) p->window = (uint16_t)iv;
        else if (!strcmp(field, "chksum")) { p->l4sum = (uint16_t)iv; p->auto_fields &= ~(unsigned)AUTO_TCP_CSUM; }
        else if (!strcmp(field, "urgptr")) p->urgptr = (uint16_t)iv;
        else return -1;
        return 0;
    }
    case LAYER_UDP:
        if (want_int(v, &iv) < 0)
            return -1;
        if (!strcmp(field, "sport")) p->sport = (uint16_t)iv;
        else if (!strcmp(field, "dport")) p->dport = (uint16_t)iv;
        else if (!strcmp(field, "len")) { p->udplen = (uint16_t)iv; p->auto_fields &= ~(unsigned)AUTO_UDP_LEN; }
        else if (!strcmp(field, "chksum")) { p->l4sum = (uint16_t)iv; p->auto_fields &= ~(unsigned)AUTO_UDP_CSUM; }
        else return -1;
        return 0;
    case LAYER_DNS:
        if (!strcmp(field, "qd"))
            return v->is_str ? set_qname(p, v->s) : -1;
        if (want_int(v, &iv) < 0)
            return -1;
        if (!strcmp(field, "id")) dns_set16(p, 0, (uint16_t)iv);
        else if (!strcmp(field, "qr")) set_dns_bit(p, 15, 1, iv);
        else if (!strcmp(field, "opcode")) set_dns_bit(p, 11, 4, iv);
        else if (!strcmp(field, "aa")) set_dns_bit(p, 10, 1, iv);
        else if (!strcmp(field, "tc")) set_dns_bit(p, 9, 1, iv);
        else if (!strcmp(field, "rd")) set_dns_bit(p, 8, 1, iv);
        else if (!strcmp(field, "ra")) set_dns_bit(p, 7, 1, iv);
        else if (!strcmp(field, "z")) set_dns_bit(p, 6, 1, iv);
        else if (!strcmp(field, "ad")) set_dns_bit(p, 5, 1, iv);
        else if (!strcmp(field, "cd")) set_dns_bit(p, 4, 1, iv);
        else if (!strcmp(field, "rcode")) set_dns_bit(p, 0, 4, iv);
        else if (!strcmp(field, "qdcount")) dns_set16(p, 4, (uint16_t)iv);
        else if (!strcmp(field, "ancount")) dns_set16(p, 6, (uint16_t)iv);
        else if (!strcmp(field, "nscount")) dns_set16(p, 8, (uint16_t)iv);
        else if (!strcmp(field, "arcount")) dns_set16(p, 10, (uint16_t)iv);
        else return -1;
        return 0;
    case LAYER_DNSQR: {
        size_t e;
        if (!strcmp(field, "qname")) {
            sbuf b;
            int rc;
            sb_init(&b);
            gval_print(&b, v);
            rc = set_qname(p, b.data);
            sb_free(&b);
            return rc;
        }
        if (want_int(v, &iv) < 0 || !dnsqr_present(p, &e))
            return -1;
        if (!strcmp(field, "qtype")) dns_set16(p, e, (uint16_t)iv);
        else if (!strcmp(field, "qclass")) dns_set16(p, e + 2, (uint16_t)iv);
        else return -1;
        return 0;
    }
    default:
        return -1;
    }
}

/* ---- DNS compression ----------------------------------------------------- */

int pkt_dns_compress(gpkt *p)
{
    size_t e, name_len;
    sbuf name, out;
    const char *q;
    const char *dot;
    size_t first_len;
    uint16_t qtype, qclass;
    if (p->l4 == LAYER_TCP)
        return -1; /* Geneva: NotImplementedError for DNS over TCP */
    if (!dnsqr_present(p, &e))
        return 0;
    sb_init(&name);
    if (!dns_read_name(p->payload, p->payload_len, 12, &name)) {
        sb_free(&name);
        return 0;
    }
    q = name.data;
    if (strcmp(q, ".") == 0) {
        sb_free(&name);
        return 0;
    }
    qtype = (uint16_t)((p->payload[e] << 8) | p->payload[e + 1]);
    qclass = (uint16_t)((p->payload[e + 2] << 8) | p->payload[e + 3]);
    dot = strchr(q, '.');
    first_len = dot ? (size_t)(dot - q) : strlen(q);
    if (first_len > 63)
        first_len = 63;
    name_len = e; /* offset of qtype */

    sb_init(&out);
    sb_append(&out, p->payload, 12);
    out.data[4] = 0;
    out.data[5] = 2; /* qdcount = 2 */
    {
        /* first question: <first label> <pointer to second question name> */
        uint8_t l = (uint8_t)first_len;
        uint16_t ptr = (uint16_t)(0xC000 | (12 + 1 + first_len + 2 + 4));
        uint8_t tail[6] = {(uint8_t)(ptr >> 8), (uint8_t)ptr, (uint8_t)(qtype >> 8),
                           (uint8_t)qtype,      (uint8_t)(qclass >> 8), (uint8_t)qclass};
        sb_append(&out, &l, 1);
        sb_append(&out, q, first_len);
        sb_append(&out, tail, 6);
    }
    {
        /* second question: the remaining labels */
        uint8_t tail[4] = {(uint8_t)(qtype >> 8), (uint8_t)qtype, (uint8_t)(qclass >> 8),
                           (uint8_t)qclass};
        dns_encode_name(&out, dot ? dot + 1 : "");
        sb_append(&out, tail, 4);
    }
    /* keep answer/authority/additional records (e.g. EDNS OPT) after the questions */
    if (name_len + 4 < p->payload_len)
        sb_append(&out, p->payload + name_len + 4, p->payload_len - name_len - 4);

    pkt_set_payload(p, (const uint8_t *)out.data, out.len);
    p->auto_fields |= AUTO_IP_LEN | AUTO_IP_CSUM | AUTO_V6_PLEN | AUTO_UDP_LEN | AUTO_UDP_CSUM;
    sb_free(&out);
    sb_free(&name);
    return 1;
}

/* ---- generation ---------------------------------------------------------- */

static void gen_load(gval *out)
{
    static const char alnum[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    switch (rng_index(4)) {
    case 0: gval_str(out, ""); break;
    case 1: gval_str(out, "__DNS_REQUEST__"); break;
    case 2: gval_str(out, "__HTTP_REQUEST__"); break;
    default: {
        char s[11];
        for (int i = 0; i < 10; i++)
            s[i] = alnum[rng_index(sizeof(alnum) - 1)];
        s[10] = 0;
        gval_str(out, s);
    }
    }
}

int field_gen(layer_id layer, const char *field, gval *out)
{
    char buf[64];
    gval_int(out, 0);
    if (!layer_has_field(layer, field))
        return -1;
    if (!strcmp(field, "load")) {
        gen_load(out);
        return 0;
    }
    switch (layer) {
    case LAYER_IP:
        if (!strcmp(field, "version") || !strcmp(field, "ihl")) gval_int(out, rng_range(0, 15));
        else if (!strcmp(field, "tos") || !strcmp(field, "ttl") || !strcmp(field, "proto")) gval_int(out, rng_range(0, 255));
        else if (!strcmp(field, "len")) gval_int(out, rng_range(1, 500));
        else if (!strcmp(field, "id")) gval_int(out, rng_range(0, 65535));
        else if (!strcmp(field, "flags")) { ip_flags_str((uint8_t)rng_range(0, 7), buf); gval_str(out, buf); }
        else if (!strcmp(field, "frag")) gval_int(out, rng_range(0, 8191));
        else if (!strcmp(field, "chksum")) gval_int(out, rng_range(1, 65535));
        else if (!strcmp(field, "src") || !strcmp(field, "dst")) {
            uint32_t a = rng_u32();
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a >> 24, (a >> 16) & 255, (a >> 8) & 255, a & 255);
            gval_str(out, buf);
        } else return -1;
        return 0;
    case LAYER_IPV6:
        if (!strcmp(field, "version")) gval_int(out, rng_range(0, 15));
        else if (!strcmp(field, "tc") || !strcmp(field, "nh") || !strcmp(field, "hlim")) gval_int(out, rng_range(0, 255));
        else if (!strcmp(field, "fl")) gval_int(out, rng_range(0, 0xfffff));
        else if (!strcmp(field, "plen")) gval_int(out, rng_range(0, 65535));
        else if (!strcmp(field, "src") || !strcmp(field, "dst")) {
            uint8_t a[16];
            rng_bytes(a, sizeof(a));
            inet_ntop(AF_INET6, a, buf, sizeof(buf));
            gval_str(out, buf);
        } else return -1;
        return 0;
    case LAYER_TCP: {
        int oi = opt_index(field);
        if (oi >= 0) {
            uint8_t kind = tcp_opt_table[oi].kind;
            if (kind == 2) gval_int(out, rng_range(0, 65535));
            else if (kind == 3) gval_int(out, rng_range(0, 255));
            else if (kind == 8) gval_int(out, rng_range(0, 4294967294LL));
            else if (kind == 14 || kind == 28) gval_int(out, rng_range(0, 255));
            else {
                uint8_t b[16];
                sbuf s;
                int n = tcp_opt_table[oi].gen_len;
                rng_bytes(b, (size_t)n);
                sb_init(&s);
                hex_encode(&s, b, (size_t)n);
                out->is_str = 1;
                out->s = sb_take(&s);
            }
            return 0;
        }
        if (!strcmp(field, "sport") || !strcmp(field, "dport") || !strcmp(field, "urgptr")) gval_int(out, rng_range(0, 65535));
        else if (!strcmp(field, "seq") || !strcmp(field, "ack")) gval_int(out, rng_range(0, 4294967295LL));
        else if (!strcmp(field, "dataofs")) gval_int(out, rng_range(1, 15));
        else if (!strcmp(field, "reserved")) gval_int(out, rng_range(0, 7));
        else if (!strcmp(field, "flags")) {
            static const char *real[] = {"S", "A", "SA", "PA", "FA", "R", "P", "F", "RA", ""};
            if (rng_chance(0.5)) {
                gval_str(out, real[rng_index(ARRAY_LEN(real))]);
            } else {
                tcp_flags_str((uint16_t)rng_range(0, 0x1ff), buf);
                gval_str(out, buf);
            }
        } else if (!strcmp(field, "window")) gval_int(out, 10 * rng_range(1, 19));
        else if (!strcmp(field, "chksum")) gval_int(out, rng_range(1, 65535));
        else return -1;
        return 0;
    }
    case LAYER_UDP:
        gval_int(out, rng_range(0, 65535));
        return 0;
    case LAYER_DNS:
        if (!strcmp(field, "qd")) return -1;
        if (!strcmp(field, "opcode") || !strcmp(field, "rcode")) gval_int(out, rng_range(0, 15));
        else if (!strcmp(field, "id") || str_ends(field, "count")) gval_int(out, rng_range(0, 65535));
        else gval_int(out, rng_range(0, 1));
        return 0;
    case LAYER_DNSQR:
        if (!strcmp(field, "qname")) gval_str(out, "example.com.");
        else gval_int(out, rng_range(0, 65535));
        return 0;
    default:
        return -1;
    }
}

/* ---- parsing strategy values --------------------------------------------- */

static int is_string_field(layer_id layer, const char *field)
{
    if (!strcmp(field, "load") || !strcmp(field, "src") || !strcmp(field, "dst"))
        return 1;
    if ((layer == LAYER_IP || layer == LAYER_TCP) && !strcmp(field, "flags"))
        return 1;
    if (layer == LAYER_DNSQR && !strcmp(field, "qname"))
        return 1;
    if (layer == LAYER_DNS && !strcmp(field, "qd"))
        return 1;
    return 0;
}

int field_parse(layer_id layer, const char *field, const char *text, gval *out)
{
    int64_t iv;
    int oi;
    gval_int(out, 0);
    if (!layer_has_field(layer, field))
        return -1;
    if (!strcmp(field, "load")) {
        gval_str(out, text); /* always a string (Geneva could turn "123" into an int) */
        return 0;
    }
    oi = layer == LAYER_TCP ? opt_index(field) : -1;
    if (oi >= 0) {
        if (!tcp_opt_table[oi].is_int) {
            uint8_t tmp[64];
            /* byte-valued options are hex strings */
            if (hex_decode(text, tmp, sizeof(tmp)) < 0)
                return -1;
            gval_str(out, text);
            return 0;
        }
        if (!*text) {
            gval_str(out, "");
            return 0;
        }
        if (parse_i64(text, &iv) < 0 || iv < 0)
            return -1;
        gval_int(out, iv);
        return 0;
    }
    if (parse_i64(text, &iv) == 0) {
        gval_int(out, iv);
        return 0;
    }
    if (!is_string_field(layer, field))
        return -1;
    if (!strcmp(field, "flags")) {
        if (layer == LAYER_TCP) {
            uint16_t f;
            if (tcp_flags_parse(text, &f) < 0)
                return -1;
        } else {
            uint8_t f;
            if (ip_flags_parse(text, &f) < 0)
                return -1;
        }
    }
    gval_str(out, text);
    return 0;
}

/* ---- restrictions (evolve --protos/--fields/--disable-fields) ------------- */

static int g_layer_allowed[LAYER_COUNT] = {1, 1, 1, 1, 1, 1};
static unsigned g_field_disabled[LAYER_COUNT]; /* bitmask over field index */

void fields_reset_restrictions(void)
{
    for (int i = 0; i < LAYER_COUNT; i++) {
        g_layer_allowed[i] = 1;
        g_field_disabled[i] = 0;
    }
}

int layer_is_allowed(layer_id id) { return id >= 0 && id < LAYER_COUNT && g_layer_allowed[id]; }

int field_is_allowed(layer_id id, const char *field)
{
    const char *const *f = layer_fields(id);
    if (!layer_is_allowed(id) || !f)
        return 0;
    for (int i = 0; f[i]; i++)
        if (!strcmp(f[i], field))
            return !(g_field_disabled[id] & (1u << i));
    return 0;
}

size_t layer_allowed_fields(layer_id id, const char **out, size_t cap)
{
    const char *const *f = layer_fields(id);
    size_t n = 0;
    if (!layer_is_allowed(id) || !f)
        return 0;
    for (int i = 0; f[i] && n < cap; i++)
        if (!(g_field_disabled[id] & (1u << i)))
            out[n++] = f[i];
    return n;
}

static int csv_has(const char *csv, const char *item, size_t n, int ci)
{
    const char *s = csv;
    while (s && *s) {
        const char *c = strchr(s, ',');
        size_t l = c ? (size_t)(c - s) : strlen(s);
        if (l == n && (ci ? str_ieqn(s, item, n) : strncmp(s, item, n) == 0))
            return 1;
        s = c ? c + 1 : NULL;
    }
    return 0;
}

int fields_restrict(const char *protos, const char *fields, const char *disabled, sbuf *msg)
{
    int any_layer = 0;
    fields_reset_restrictions();
    for (int l = 0; l < LAYER_COUNT; l++) {
        const char *const *f = all_fields[l];
        for (int i = 0; f[i]; i++) {
            size_t n = strlen(f[i]);
            if (fields && *fields && !csv_has(fields, f[i], n, 1))
                g_field_disabled[l] |= 1u << i;
            if (disabled && *disabled && csv_has(disabled, f[i], n, 0))
                g_field_disabled[l] |= 1u << i;
        }
    }
    if (protos && *protos) {
        for (int l = 0; l < LAYER_COUNT; l++)
            g_layer_allowed[l] = csv_has(protos, layer_names[l], strlen(layer_names[l]), 1);
        /* report unknown protocol names */
        for (const char *s = protos; s && *s;) {
            const char *c = strchr(s, ',');
            size_t l = c ? (size_t)(c - s) : strlen(s);
            char name[32];
            snprintf(name, sizeof(name), "%.*s", (int)MIN(l, sizeof(name) - 1), s);
            if (layer_by_name(name) == LAYER_NONE && msg)
                sb_printf(msg, "%s is not a supported protocol; ", name);
            s = c ? c + 1 : NULL;
        }
    }
    for (int l = 0; l < LAYER_COUNT; l++) {
        const char *tmp[32];
        if (g_layer_allowed[l] && layer_allowed_fields((layer_id)l, tmp, 32) == 0)
            g_layer_allowed[l] = 0; /* a layer with no usable fields is dropped */
        any_layer |= g_layer_allowed[l];
    }
    if (!any_layer) {
        if (msg)
            sb_puts(msg, "cannot evolve with no available packet layers");
        return -1;
    }
    return 0;
}
