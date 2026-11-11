/*
 * Fuzz targets (fuzz.h): one function per reader of untrusted input, the
 * built-in seeds they start from and the mutator of "selftest --fuzz".
 */
#include "ext/fuzz.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext/blob.h"
#include "ext/cfgfile.h"
#include "ext/ctrack.h"
#include "ext/ext.h"
#include "ext/fwx.h"
#include "ext/hostlist.h"
#include "ext/inflate.h"
#include "ext/ipset.h"
#include "ext/l7.h"
#include "ext/markers.h"
#include "ext/profile.h"
#include "ext/quic.h"
#include "ext/range.h"
#include "ext/tls.h"
#include "ext_opt.h"
#include "json.h"
#include "library.h"
#include "log.h"
#include "pcap.h"
#include "pkt.h"
#include "ports.h"
#include "rng.h"
#include "sdb.h"
#include "strategy.h"
#include "util.h"

#define FUZZ_MAX 65536 /* bytes of one input a target looks at */

void xfuzz_fail(const char *what, const char *file, int line)
{
    fprintf(stderr, "geneva fuzz: check failed: %s (%s:%d)\n", what, file, line);
    fflush(stderr);
    abort();
}

/* ---- helpers ------------------------------------------------------------------ */

/* the input as a C string (stops at a NUL), freed by the caller */
static char *text_of(const uint8_t *d, size_t n)
{
    return xstrndup((const char *)d, n > FUZZ_MAX ? FUZZ_MAX : n);
}

static void add_str(xfuzz_add_fn add, void *ud, const char *s)
{
    add(ud, (const uint8_t *)s, strlen(s));
}

/* An IPv4 or IPv6 packet with a TCP or UDP header (or proto's bare
 * payload), its lengths and checksums filled in, into out; its length. */
static size_t mk_pkt(uint8_t *out, size_t cap, int v6, int proto, uint16_t sport, uint16_t dport, uint8_t flags,
                     const uint8_t *pl, size_t pln)
{
    uint8_t b[2048];
    size_t ih = v6 ? 40 : 20, lh = proto == 6 ? 20 : proto == 17 ? 8 : 0, n = ih + lh + pln, len = 0;
    gpkt *p;
    uint8_t *r;
    if (n > sizeof(b))
        return 0;
    memset(b, 0, n);
    if (v6) {
        b[0] = 0x60;
        b[4] = (uint8_t)((n - 40) >> 8);
        b[5] = (uint8_t)(n - 40);
        b[6] = (uint8_t)proto;
        b[7] = 64;
        b[8] = 0x20, b[9] = 0x01, b[10] = 0x0d, b[11] = 0xb8, b[23] = 1;
        b[24] = 0x20, b[25] = 0x01, b[26] = 0x0d, b[27] = 0xb8, b[39] = 2;
    } else {
        b[0] = 0x45;
        b[2] = (uint8_t)(n >> 8);
        b[3] = (uint8_t)n;
        b[6] = 0x40;
        b[8] = 64;
        b[9] = (uint8_t)proto;
        b[12] = 10, b[15] = 1, b[16] = 10, b[19] = 2;
    }
    if (lh) {
        uint8_t *l = b + ih;
        l[0] = (uint8_t)(sport >> 8), l[1] = (uint8_t)sport, l[2] = (uint8_t)(dport >> 8), l[3] = (uint8_t)dport;
        if (proto == 6) {
            l[4] = 0x10, l[7] = 1;
            if (flags & 0x10)
                l[8] = 0x20, l[11] = 1;
            l[12] = 0x50;
            l[13] = flags;
            l[14] = 0xff, l[15] = 0xff;
        } else {
            l[4] = (uint8_t)((8 + pln) >> 8);
            l[5] = (uint8_t)(8 + pln);
        }
    }
    if (pln)
        memcpy(b + ih + lh, pl, pln);
    p = pkt_parse(b, n);
    if (!p)
        return 0;
    pkt_mark_dirty(p);
    r = pkt_bytes(p, &len);
    pkt_free(p);
    if (!r || len > cap) {
        free(r);
        return 0;
    }
    memcpy(out, r, len);
    free(r);
    return len;
}

static const char http_get[] = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: curl/8.5.0\r\n"
                               "Accept: */*\r\n\r\n";
static const char http_reply[] = "HTTP/1.1 302 Found\r\nLocation: http://warning.example/\r\nContent-Length: 0\r\n\r\n";

/* a TLS ClientHello record for example.com; its length */
static size_t mk_tls(uint8_t *out, size_t cap, const char *sni, size_t total)
{
    return blob_make_tls(sni, total, 7, out, cap);
}

/* The sample payloads the seeds are made of: index i (0 when past the
 * end), into out; its length */
static size_t sample(int i, uint8_t *out, size_t cap)
{
    size_t n = 0;
    switch (i) {
    case 0:
        return mk_tls(out, cap, "www.example.com", 0);
    case 1:
        n = strlen(http_get);
        break;
    case 2:
        n = strlen(http_reply);
        memcpy(out, http_reply, n);
        return n;
    case 3:
        return blob_make_quic("www.example.com", 7, out, cap);
    case 4: {
        /* a DNS query for example.com */
        static const uint8_t q[] = {0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l',
                                    'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
        memcpy(out, q, sizeof(q));
        return sizeof(q);
    }
    case 5:
        return mk_tls(out, cap, "rutracker.org", 517);
    default:
        return 0;
    }
    memcpy(out, http_get, n);
    return n;
}

/* ---- pkt: Geneva's packet reader and fields ------------------------------------ */

static void t_pkt(const uint8_t *d, size_t n)
{
    gpkt *p = pkt_parse(d, n), *q;
    sbuf s;
    uint8_t *b;
    size_t len;
    if (!p)
        return;
    sb_init(&s);
    pkt_describe(p, &s);
    for (int l = 0; l < LAYER_COUNT; l++) {
        const char *const *f;
        if (!pkt_has_layer(p, (layer_id)l))
            continue;
        for (f = layer_fields((layer_id)l); f && *f; f++) {
            gval v;
            if (pkt_get(p, (layer_id)l, *f, &v) == 0) {
                sb_reset(&s);
                gval_print(&s, &v);
                gval_free(&v);
            }
        }
    }
    b = pkt_bytes(p, &len);
    free(b);
    /* tampers: a generated value in every field, as Geneva's fuzzing does */
    q = pkt_copy(p);
    for (int l = 0; l < LAYER_COUNT; l++) {
        const char *const *f;
        if (!pkt_has_layer(q, (layer_id)l))
            continue;
        for (f = layer_fields((layer_id)l); f && *f; f++) {
            gval v;
            if (field_gen((layer_id)l, *f, &v) == 0) {
                pkt_set(q, (layer_id)l, *f, &v);
                gval_free(&v);
            }
        }
    }
    if (pkt_has_layer(q, LAYER_DNSQR))
        pkt_dns_compress(q);
    b = pkt_bytes(q, &len);
    free(b);
    sb_reset(&s);
    pkt_describe(q, &s);
    pkt_free(q);
    pkt_free(p);
    sb_free(&s);
}

static void s_pkt(xfuzz_add_fn add, void *ud)
{
    uint8_t pl[1500], b[2048];
    size_t n, l;
    for (int i = 0; (n = sample(i, pl, sizeof(pl))) || i < 6; i++) {
        int udp = i == 3 || i == 4;
        for (int v6 = 0; v6 < 2; v6++)
            if ((l = mk_pkt(b, sizeof(b), v6, udp ? 17 : 6, 40000, udp ? (i == 4 ? 53 : 443) : (i == 1 ? 80 : 443),
                            0x18, pl, n)))
                add(ud, b, l);
    }
    if ((l = mk_pkt(b, sizeof(b), 0, 6, 40000, 443, 0x02, NULL, 0)))
        add(ud, b, l);
    if ((l = mk_pkt(b, sizeof(b), 1, 6, 443, 40000, 0x12, NULL, 0)))
        add(ud, b, l);
    {
        /* an ICMP time-exceeded quoting a TCP SYN */
        uint8_t ic[8 + 40] = {11, 0, 0, 0, 0, 0, 0, 0};
        uint8_t syn[64];
        size_t sl = mk_pkt(syn, sizeof(syn), 0, 6, 40000, 443, 0x02, NULL, 0);
        if (sl == 40) {
            memcpy(ic + 8, syn, sl);
            if ((l = mk_pkt(b, sizeof(b), 0, 1, 0, 0, 0, ic, sizeof(ic))))
                add(ud, b, l);
        }
    }
}

/* ---- strategy: the strategy language with the x-actions ----------------------- */

static const char *const ext_strategies[] = {
    "[TCP:flags:PA]-xfake{blob=fake_default_tls;ttl=3;md5}(xdisorder{pos=1,midsld},)-| \\/",
    "[TCP:flags:PA]-xtlsclone{blob=c;sni_first=a.example}(xfake{blob=c;ttl=3},)-| \\/",
    "[TCP:flags:PA]-xwhen{iff=FLOW:n:<3}(xrepeat{repeats=2}(xfake{blob=0x41;ttl=1},),)-| \\/",
    "[TCP:flags:PA]-xfake{blob=fake_default_tls;tlsmod=rnd,dupsid;ip_ttl=3;tcp_md5}-| \\/",
    "[TCP:flags:PA]-xfake{blob=fake_default_http;payload=all}(xtcpseg{pos=0,4;payload=all},)-| \\/",
    "[TCP:flags:PA]-xsplit{pos=1,host,midsld}-| \\/",
    "[TCP:flags:PA]-xdisorder{pos=5,host;seqovl=2}-| \\/",
    "[TCP:flags:PA]-xfakedsplit{pos=method+2;pattern=0x00ff;nofake3}-| \\/",
    "[TCP:flags:PA]-xfakeddisorder{pos=midsld;seqovl=1}-| \\/",
    "[TCP:flags:PA]-xhostfake{midhost=midsld;disorder_after=-5;nofake1}-| \\/",
    "[TCP:flags:PA]-xhttp{domcase;hostcase=hoSt;methodeol;unixeol}-| \\/",
    "[TCP:flags:PA]-xmod{seq=-5;ack=0x10;ts=-50;flags+=SYN,urg;flags-=PSH}-| \\/",
    "[TCP:flags:PA]-xmod{ip6ext=hopbyhop,destopt,routing,destopt2,ah;ttl=7}-| \\/",
    "[TCP:flags:PA]-xmod{nopdel}(xmod{tsup},)-| \\/",
    "[TCP:flags:PA]-xlog{msg=hi;pkt;hex}(xmod{ttl=9},)-| \\/",
    "[TCP:flags:PA]-xcutoff{dir=both}(xsplit{pos=4},)-| \\/",
    "[TCP:flags:PA]-xstop{iff=L7:payload:http_req}(xsplit{pos=2},)-| \\/",
    "[TCP:flags:PA]-xtag{pattern=GET;payload=my}(xsend{ipfrag;ipfrag_pos_tcp=16;ipfrag_disorder},)-| \\/",
    "[TCP:flags:S]-xsyndata{blob=fake_default_tls}-| \\/",
    "[TCP:flags:PA]-xrst{ttl=2}-| \\/",
    "[TCP:flags:SA]-xsynacksplit-| \\/",
    "\\/ [TCP:flags:SA]-xwssize{wsize=1;scale=6;forced_cutoff=http_req,tls_client_hello}-|",
    "[UDP:dport:443]-xfake{blob=fake_default_quic;repeats=2}-| \\/",
    "[UDP:dport:443]-xudplen{increment=2}-| \\/",
    "[UDP:dport:6881]-xdhtdn-| \\/",
    "[L7:host:example.com]-xfake{blob=fake_default_tls;ttl=4}-| \\/",
    "[FLOW:n:<5]-xmod{ttl=5}-| \\/",
    "[TCP:flags:PA]-xwhen{iff=cond_payload_str;pattern=GET}(xsplit{pos=method+2},xmod{ttl=6})-| \\/",
    "[FLOW:n:1-]-xoob{urp=e;char=X}-| \\/",
    "[FLOW:n:1-]-xoob{urp=midsld}-| \\/",
    "[FLOW:n:1-]-xtlsrec{pos=sniext+1}-| \\/",
    "[TCP:flags:PA]-xdrip{n=3;delay=5}-| \\/",
    NULL,
};

static void t_strategy(const uint8_t *d, size_t n)
{
    char *text = text_of(d, n);
    sbuf err, a, b;
    strategy *s, *s2;
    sb_init(&err);
    sb_init(&a);
    sb_init(&b);
    s = strategy_parse(text, &err);
    if (s) {
        jw w;
        strategy_print(s, &a);
        s2 = strategy_parse(a.data, &err);
        if (!s2)
            fprintf(stderr, "geneva fuzz: \"%s\" does not parse back: %s\n", a.data, err.data);
        XFUZZ_CHECK(s2 != NULL);
        strategy_print(s2, &b);
        /* Geneva's quirk, kept: a trigger value ending in "]" loses one
         * "]" each time it is read ("[TCP:load:a]]-drop-|" prints as
         * "[TCP:load:a]-drop-|"), so such a text is not stable */
        if (strstr(a.data, "]]"))
            sb_reset(&b), sb_puts(&b, a.data);
        if (strcmp(a.data, b.data))
            fprintf(stderr, "geneva fuzz: \"%s\" prints back as \"%s\"\n", a.data, b.data);
        XFUZZ_CHECK(strcmp(a.data, b.data) == 0);
        sb_reset(&b);
        strategy_pretty(s, &b);
        sb_reset(&b);
        jw_init(&w, &b);
        strategy_json(s, &w);
        (void)strategy_len(s);
        strategy_free(s2);
        strategy_free(s);
    }
    sb_free(&err);
    sb_free(&a);
    sb_free(&b);
    free(text);
}

static void s_strategy(xfuzz_add_fn add, void *ud)
{
    size_t n;
    const lib_entry *e = library_entries(&n);
    for (size_t i = 0; i < n; i++)
        add_str(add, ud, e[i].strategy);
    for (int i = 0; ext_strategies[i]; i++)
        add_str(add, ud, ext_strategies[i]);
}

/* ---- apply: packets through strategies, as "geneva apply --ext" does ---------- */

/* The strategies: the library's, then ext_strategies */
static size_t apply_count(void)
{
    size_t n, k = 0;
    library_entries(&n);
    while (ext_strategies[k])
        k++;
    return n + k;
}

static const char *apply_text(size_t i)
{
    size_t n;
    const lib_entry *e = library_entries(&n);
    return i < n ? e[i].strategy : ext_strategies[i - n];
}

static void apply_one(strategy *st, gpkt *p, strat_dir dir, int run, void *xctx)
{
    pktlist out = {0};
    if (run > 0 && st) {
        strategy_apply_x(st, p, dir, &out, xctx);
        if (dir == DIR_IN)
            while (out.n > 1)
                pkt_free(out.v[--out.n]);
    } else {
        pktlist_push(&out, p);
    }
    for (size_t i = 0; i < out.n; i++) {
        size_t len;
        uint8_t *b = pkt_bytes(out.v[i], &len);
        if (b && len) {
            /* what the engine sends must read back as a packet */
            gpkt *r = pkt_parse(b, len);
            pkt_free(r);
        }
        free(b);
    }
    pktlist_free(&out);
}

static void apply_replay(void *ud, const uint8_t *raw, size_t len, strat_dir dir, unsigned piece, unsigned pieces,
                         void *xctx)
{
    gpkt *p = pkt_parse(raw, len);
    sbuf s;
    (void)ud, (void)piece, (void)pieces;
    if (!p)
        return;
    if (!xctx) {
        apply_one(NULL, p, dir, 0, NULL);
        return;
    }
    sb_init(&s);
    xoff_posdebug(xctx, dir, p, &s);
    sb_free(&s);
    apply_one(xoff_strategy(xctx), p, dir, xoff_strategy(xctx) ? 1 : 0, xctx);
}

/* Input: a strategy number, then packets as [flags][length: 2 bytes][bytes]
 * (flags bit 0: inbound; the rest: 10 + flags/2 ms after the last one) */
static void t_apply(const uint8_t *d, size_t n)
{
    strategy *st;
    sbuf err;
    xoffline *xo;
    size_t off = 1;
    uint64_t now = 1000;
    if (n < 1)
        return;
    sb_init(&err);
    st = strategy_parse(apply_text(d[0] % apply_count()), &err);
    XFUZZ_CHECK(st != NULL);
    sb_free(&err);
    xo = xoff_new();
    for (int k = 0; k < 64 && off + 3 <= n; k++) {
        uint8_t flags = d[off];
        strat_dir dir = flags & 1 ? DIR_IN : DIR_OUT;
        size_t len = (size_t)d[off + 1] << 8 | d[off + 2];
        const uint8_t *raw = d + off + 3;
        gpkt *p;
        strategy *pst = st;
        int v = XOFF_RUN;
        void *xctx;
        sbuf s;
        off += 3;
        if (len > n - off)
            len = n - off;
        off += len;
        now += 10 + (flags >> 1); /* the other bits: milliseconds since the last packet */
        if (!(p = pkt_parse(raw, len)))
            continue;
        xctx = xoff_packet(xo, &pst, p, dir, now, raw, len, apply_replay, NULL, &v);
        if (v == XOFF_HOLD || v == XOFF_DROP) {
            pkt_free(p);
            continue;
        }
        sb_init(&s);
        xoff_posdebug(xctx, dir, p, &s);
        sb_free(&s);
        apply_one(pst, p, dir, v == XOFF_BYPASS ? 0 : 1, xctx);
    }
    xoff_end(xo, st, apply_replay, NULL);
    xoff_free(xo);
    strategy_free(st);
}

static void s_apply(xfuzz_add_fn add, void *ud)
{
    uint8_t pl[1500], pk[2048], in[8192];
    size_t cnt = apply_count();
    for (size_t s = 0; s < cnt && s < 256; s++) {
        int i = (int)(s % 6), udp = i == 3 || i == 4;
        size_t n = sample(i, pl, sizeof(pl)), at = 1, l;
        uint16_t dport = udp ? (i == 4 ? 53 : 443) : (i == 1 ? 80 : 443);
        in[0] = (uint8_t)s;
        /* the client's SYN, the server's SYN+ACK, then the data both ways */
        struct {
            int in, proto;
            uint8_t flags;
            const uint8_t *pl;
            size_t n;
        } seq[4] = {{0, 6, 0x02, NULL, 0}, {1, 6, 0x12, NULL, 0}, {0, udp ? 17 : 6, 0x18, pl, n},
                    {1, udp ? 17 : 6, 0x18, (const uint8_t *)http_reply, strlen(http_reply)}};
        for (int k = udp ? 2 : 0; k < 4; k++) {
            l = seq[k].in ? mk_pkt(pk, sizeof(pk), (int)(s & 1), seq[k].proto, dport, 40000, seq[k].flags,
                                   seq[k].pl, seq[k].n)
                          : mk_pkt(pk, sizeof(pk), (int)(s & 1), seq[k].proto, 40000, dport, seq[k].flags,
                                   seq[k].pl, seq[k].n);
            if (!l || at + 3 + l > sizeof(in))
                continue;
            in[at] = (uint8_t)seq[k].in;
            in[at + 1] = (uint8_t)(l >> 8);
            in[at + 2] = (uint8_t)l;
            memcpy(in + at + 3, pk, l);
            at += 3 + l;
        }
        add(ud, in, at);
    }
}

/* ---- pcap: the capture reader of "geneva apply" ------------------------------ */

static void t_pcap(const uint8_t *d, size_t n)
{
    FILE *f;
    pcap_reader *r;
    pcap_rec rec;
    sbuf err;
    if (!n)
        return;
#ifdef _WIN32
    f = tmpfile();
    if (!f)
        return;
    fwrite(d, 1, n, f);
    rewind(f);
#else
    f = fmemopen((void *)d, n, "rb");
    if (!f)
        return;
#endif
    sb_init(&err);
    r = pcap_read_fp(f, &err);
    if (r) {
        for (int k = 0; k < 1000 && pcap_next(r, &rec, &err) > 0; k++)
            if (rec.ip) {
                XFUZZ_CHECK(rec.ip_len <= rec.caplen);
                pkt_free(pkt_parse(rec.ip, rec.ip_len));
            }
        pcap_close_read(r);
    } /* (a failed pcap_read_fp closes f) */
    sb_free(&err);
}

static void put32(sbuf *b, uint32_t v)
{
    sb_append(b, &v, 4); /* host order, as pcap's magic tells */
}

static void put16(sbuf *b, uint16_t v)
{
    sb_append(b, &v, 2);
}

static void s_pcap(xfuzz_add_fn add, void *ud)
{
    uint8_t pl[1500], pk[2048];
    int links[] = {LINKTYPE_RAW, LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_NULL};
    for (size_t li = 0; li < ARRAY_LEN(links); li++) {
        sbuf b;
        sb_init(&b);
        put32(&b, 0xa1b2c3d4);
        put16(&b, 2);
        put16(&b, 4);
        put32(&b, 0);
        put32(&b, 0);
        put32(&b, 65535);
        put32(&b, (uint32_t)links[li]);
        for (int i = 0; i < 3; i++) {
            size_t n = sample(i, pl, sizeof(pl)), l = mk_pkt(pk, sizeof(pk), i == 2, 6, 40000, 443, 0x18, pl, n);
            uint8_t hdr[16] = {0};
            size_t hl = 0;
            if (links[li] == LINKTYPE_ETHERNET) {
                hl = 14;
                hdr[12] = i == 2 ? 0x86 : 0x08, hdr[13] = i == 2 ? 0xdd : 0x00;
            } else if (links[li] == LINKTYPE_LINUX_SLL) {
                hl = 16;
                hdr[14] = i == 2 ? 0x86 : 0x08, hdr[15] = i == 2 ? 0xdd : 0x00;
            } else if (links[li] == LINKTYPE_NULL) {
                uint32_t af = i == 2 ? 30 : 2;
                hl = 4;
                memcpy(hdr, &af, 4);
            }
            put32(&b, 1700000000u + (uint32_t)i);
            put32(&b, 0);
            put32(&b, (uint32_t)(hl + l));
            put32(&b, (uint32_t)(hl + l));
            sb_append(&b, hdr, hl);
            sb_append(&b, pk, l);
        }
        add(ud, (const uint8_t *)b.data, b.len);
        sb_free(&b);
    }
    {
        /* pcapng: section header, interface (raw IP), one enhanced packet */
        sbuf b;
        size_t l = mk_pkt(pk, sizeof(pk), 0, 6, 40000, 443, 0x02, NULL, 0);
        sb_init(&b);
        put32(&b, 0x0a0d0d0a);
        put32(&b, 28);
        put32(&b, 0x1a2b3c4d);
        put16(&b, 1);
        put16(&b, 0);
        put32(&b, 0xffffffff);
        put32(&b, 0xffffffff);
        put32(&b, 28);
        put32(&b, 1);
        put32(&b, 20);
        put16(&b, LINKTYPE_RAW);
        put16(&b, 0);
        put32(&b, 65535);
        put32(&b, 20);
        put32(&b, 6);
        put32(&b, (uint32_t)(32 + l));
        put32(&b, 0);
        put32(&b, 0);
        put32(&b, 1);
        put32(&b, (uint32_t)l);
        put32(&b, (uint32_t)l);
        sb_append(&b, pk, l);
        put32(&b, (uint32_t)(32 + l));
        add(ud, (const uint8_t *)b.data, b.len);
        sb_free(&b);
    }
}

/* ---- json: control requests and database lines ------------------------------- */

static void walk(const json_val *v, int depth)
{
    if (!v || depth > 64)
        return;
    for (size_t i = 0; (v->type == JSON_ARR || v->type == JSON_OBJ) && i < v->n; i++)
        walk(v->items[i], depth + 1);
}

static void t_json(const uint8_t *d, size_t n)
{
    char *text = text_of(d, n);
    const char *err = NULL;
    json_val *v = json_parse(text, &err);
    sdb_rec r;
    if (v) {
        walk(v, 0);
        (void)json_get_str(v, "cmd", NULL);
        (void)json_get_int(v, "id", 0);
        (void)json_get_num(v, "fitness", 0);
        (void)json_get_bool(v, "ok", 0);
        json_free(v);
    }
    memset(&r, 0, sizeof(r));
    if (sdb_rec_parse(text, &r) == 0) {
        /* a line of the database writes back as one that reads */
        sbuf s;
        sdb_rec r2;
        sb_init(&s);
        sdb_rec_json(&r, &s);
        memset(&r2, 0, sizeof(r2));
        XFUZZ_CHECK(sdb_rec_parse(s.data, &r2) == 0);
        XFUZZ_CHECK(!strcmp(r.s, r2.s) && !strcmp(r.t, r2.t) && r.runs == r2.runs && r.ok == r2.ok);
        sdb_rec_free(&r2);
        sb_free(&s);
        sdb_rec_free(&r);
    }
    free(text);
}

static void s_json(xfuzz_add_fn add, void *ud)
{
    add_str(add, ud, "{\"cmd\":\"set_strategy\",\"strategy\":\"\\\\/\",\"id\":7}");
    add_str(add, ud, "{\"cmd\":\"stats\",\"token\":\"x\",\"list\":[1,2.5e3,-0.5,true,false,null,\"\\u0041\"]}");
    add_str(add, ud, "{\"s\":\"[TCP:flags:PA]-drop-| \\\\/\",\"t\":\"tls:example.com\",\"runs\":3,\"ok\":2,"
                     "\"fit_sum\":12.5,\"fit_best\":6.25,\"first\":1700000000000,\"last\":1700000001000,"
                     "\"last_ok\":1700000001000}");
    add_str(add, ud, "[[[[{\"a\":{\"b\":[]}}]]]]");
}

/* ---- l7: payload recognition, host names and markers ------------------------- */

static const char *const l7_markers[] = {"5",      "-1",     "host",  "host+1",  "endhost",  "endhost-1",
                                         "sld",    "midsld", "endsld", "method+2", "extlen", "sniext+1",
                                         "0",      "-200",   NULL};

static void t_l7(const uint8_t *d, size_t n)
{
    char h[256];
    int l7;
    size_t off, len;
    const uint8_t *ext;
    if (n > FUZZ_MAX)
        n = FUZZ_MAX;
    for (int tcp = 0; tcp < 2; tcp++)
        for (int srv = 0; srv < 2; srv++) {
            l7 = L7_UNKNOWN;
            (void)l7_probe(d, n, tcp, srv, !srv, 0, &l7);
        }
    l7 = L7_WIREGUARD;
    (void)l7_probe(d, n, 0, 0, 0, 0, &l7);
    (void)l7_is_http(d, n);
    (void)l7_is_http_reply(d, n);
    for (uint8_t t = 1; t <= 2; t++) {
        (void)l7_is_tls_hello(d, n, t, 0);
        (void)l7_is_tls_hello(d, n, t, 1);
        (void)l7_is_tls_hs_hello(d, n, t, 1);
    }
    (void)l7_is_quic_initial(d, n);
    (void)l7_is_xmpp_stream(d, n);
    (void)l7_is_dns_query(d, n);
    (void)l7_is_dns_response(d, n);
    (void)l7_is_dht(d, n);
    (void)l7_is_stun(d, n);
    (void)l7_is_mtproto(d, n);
    (void)l7_is_dtls(d, n);
    if (n >= 5)
        (void)l7_tls_record_len(d);
    if (n >= 4)
        (void)l7_tls_hs_len(d);
    (void)l7_tls_ext_len_off(d, n, &off);
    if (l7_tls_find_ext(d, n, 0, &ext, &len, 1)) {
        size_t slen;
        (void)l7_tls_sni_host(&ext, &len, &slen);
    }
    for (int p = 0; p < 2; p++) {
        if (l7_tls_host(d, n, h, sizeof(h), p)) {
            const uint8_t *nld;
            size_t nl;
            XFUZZ_CHECK(strlen(h) < sizeof(h));
            for (int lv = 1; lv <= 3; lv++)
                (void)l7_find_nld((const uint8_t *)h, strlen(h), lv, &nld, &nl);
        }
        (void)l7_tls_hs_host(d, n, h, sizeof(h), p);
    }
    if (l7_http_host(d, n, h, sizeof(h))) {
        XFUZZ_CHECK(strlen(h) < sizeof(h));
        (void)l7_http_dpi_redirect(d, n, h);
    }
    (void)l7_http_header(d, n, "Location", h, sizeof(h));
    (void)l7_http_reply_code(d, n);
    (void)l7_quic_crypto_hello(d, n, &off, &len);
    for (int l7p = 0; l7p < L7P_LAST; l7p++) {
        xmarker m[XMARKER_MAX];
        long pos[XMARKER_MAX];
        int k = 0;
        for (int i = 0; l7_markers[i] && k < XMARKER_MAX; i++)
            if (xmarker_parse(l7_markers[i], &m[k]) == 0)
                k++;
        for (int i = 0; i < k; i++) {
            long r = xmarker_resolve(d, n, l7p, &m[i]);
            XFUZZ_CHECK(r < 0 || (size_t)r <= n);
        }
        (void)xmarker_resolve_list(d, n, l7p, m, k, pos);
    }
}

static void s_l7(xfuzz_add_fn add, void *ud)
{
    uint8_t b[2048];
    size_t n;
    for (int i = 0; (n = sample(i, b, sizeof(b))) || i < 6; i++)
        if (n)
            add(ud, b, n);
    add_str(add, ud, "<stream:stream xmlns='jabber:client' to='example.com' version='1.0'>");
    add_str(add, ud, "POST /x HTTP/1.0\r\nhost:Example.COM:8080\r\nContent-Length: 2\r\n\r\nab");
}

/* ---- tls: SNI, tls_mod and the ClientHello clone ------------------------------ */

static void t_tls(const uint8_t *d, size_t n)
{
    char h[256];
    uint8_t hs[4096], fake[8192];
    size_t ml, fl;
    tls_modspec m;
    tls_cloneopt o;
    uint8_t *out = NULL;
    size_t outlen = 0;
    if (n > FUZZ_MAX)
        n = FUZZ_MAX;
    (void)tls_hs_sni(d, n, h, sizeof(h), &ml);
    (void)tls_rec_sni(d, n, h, sizeof(h), hs, sizeof(hs));
    /* the clone with options from the last byte */
    memset(&o, 0, sizeof(o));
    o.snt = o.snt_new = -1;
    if (n) {
        uint8_t f = d[n - 1];
        o.del_ext = f & 1;
        o.del = f & 2;
        if (f & 4)
            o.first = "first.example", o.first_len = 13;
        if (f & 8)
            o.last = "last.example.org", o.last_len = 16;
        if (f & 16)
            o.snt = f >> 5;
        if (f & 32)
            o.snt_new = 0;
    }
    if (tls_ch_clone(d, n, &o, &out, &outlen) == 0) {
        XFUZZ_CHECK(out != NULL);
        free(out);
    }
    /* tls_mod: the input as the client's ClientHello, then as the fake */
    XFUZZ_CHECK(tls_mod_parse("rnd,rndsni,dupsid,padencap", &m) == 0);
    fl = mk_tls(fake, sizeof(fake), "www.example.com", 0);
    (void)tls_mod_apply(&m, d, n, fake, &fl, sizeof(fake));
    XFUZZ_CHECK(fl <= sizeof(fake));
    if (n <= sizeof(fake) / 2) {
        XFUZZ_CHECK(tls_mod_parse("sni=a.very.long.name.example.com,dupsid", &m) == 0);
        memcpy(fake, d, n);
        fl = n;
        (void)tls_mod_apply(&m, d, n, fake, &fl, sizeof(fake));
        XFUZZ_CHECK(fl <= sizeof(fake));
    }
}

static void s_tls(xfuzz_add_fn add, void *ud)
{
    uint8_t b[2048];
    size_t n = mk_tls(b, sizeof(b), "www.example.com", 0);
    add(ud, b, n);
    if (n > 5)
        add(ud, b + 5, n - 5); /* the bare handshake message */
    n = mk_tls(b, sizeof(b), "rutracker.org", 1500);
    add(ud, b, n);
}

/* ---- quic: Initial header, decryption, CRYPTO frames -------------------------- */

static void t_quic(const uint8_t *d, size_t n)
{
    quic_initial h;
    uint8_t *out, *def;
    size_t len, dl, off = 0;
    uint64_t v;
    int full;
    long r;
    if (n > FUZZ_MAX)
        n = FUZZ_MAX;
    out = xmalloc(n + 16);
    def = xmalloc(n + 64);
    (void)quic_is_initial(d, n, &h);
    r = quic_initial_decrypt(d, n, &h, out, n + 16);
    XFUZZ_CHECK(r <= (long)n);
    /* the decrypted frames, or the input as frames itself */
    for (int k = 0; k < 2; k++) {
        const uint8_t *f = k ? d : out;
        size_t fn = k ? n : r > 0 ? (size_t)r : 0;
        uint8_t cs[8192];
        if (quic_crypto_stream(f, fn, cs, sizeof(cs), &len) == 0)
            XFUZZ_CHECK(len <= sizeof(cs));
        dl = n + 64;
        if (l7_quic_defrag(f, fn, def, &dl, &full)) {
            size_t ho, hl;
            XFUZZ_CHECK(dl <= n + 64);
            if (l7_quic_crypto_hello(def, dl, &ho, &hl))
                XFUZZ_CHECK(ho + hl <= dl);
        }
    }
    while (off < n && quic_varint(d, n, &off, &v) == 0)
        ;
    if (n >= 5)
        (void)l7_quic_draft((uint32_t)d[1] << 24 | (uint32_t)d[2] << 16 | (uint32_t)d[3] << 8 | d[4]);
    free(out);
    free(def);
}

static void s_quic(xfuzz_add_fn add, void *ud)
{
    uint8_t b[2048], t[2048];
    size_t n = blob_make_quic("www.example.com", 7, b, sizeof(b)), tl;
    if (n)
        add(ud, b, n);
    /* CRYPTO frames as they come out of the decryption: two pieces of a
     * ClientHello out of order, PADDING and PING around them */
    tl = mk_tls(t, sizeof(t), "www.example.com", 0);
    if (tl > 105) {
        size_t a = 100, at = 0;
        uint8_t *f = b;
        size_t hl = tl - 5;
        const uint8_t *hs = t + 5;
        f[at++] = 1; /* PING */
        f[at++] = 6;
        f[at++] = 0x40 | (uint8_t)(a >> 8), f[at++] = (uint8_t)a; /* offset a */
        f[at++] = 0x40 | (uint8_t)((hl - a) >> 8), f[at++] = (uint8_t)(hl - a);
        memcpy(f + at, hs + a, hl - a);
        at += hl - a;
        f[at++] = 6;
        f[at++] = 0;
        f[at++] = 0x40 | (uint8_t)(a >> 8), f[at++] = (uint8_t)a;
        memcpy(f + at, hs, a);
        at += a;
        memset(f + at, 0, 20);
        at += 20;
        add(ud, f, at);
    }
}

/* ---- inflate: gzip and zlib of the list files --------------------------------- */

static void t_inflate(const uint8_t *d, size_t n)
{
    uint8_t *out = NULL;
    size_t outlen = 0, used = 0;
    int r = xinf_unwrap(d, n, 1 << 20, &out, &outlen);
    if (r == 0)
        XFUZZ_CHECK(outlen <= 1 << 20);
    free(out);
    out = NULL;
    r = xinf_raw(d, n, 1 << 16, &out, &outlen, &used);
    if (r == 0)
        XFUZZ_CHECK(outlen <= 1 << 16 && used <= n);
    free(out);
    (void)xinf_is_gzip(d, n);
    (void)xinf_crc32(0, d, n);
}

static void s_inflate(xfuzz_add_fn add, void *ud)
{
    static const uint8_t z[] = {0x78, 0xda, 0x4b, 0xad, 0x48, 0xcc, 0x2d, 0xc8, 0x49, 0xd5, 0x4b, 0xce,
                                0xcf, 0xe5, 0xd2, 0xd2, 0x4b, 0x85, 0xf2, 0xf2, 0x8b, 0xd2, 0xb9, 0xe2,
                                0x8a, 0x4b, 0x8a, 0x32, 0x93, 0x4b, 0x60, 0x62, 0x5c, 0x8a, 0xa9, 0x15,
                                0xa9, 0xb9, 0x05, 0x70, 0x3e, 0x58, 0x07, 0x00, 0xc9, 0x1c, 0x16, 0x88};
    static const uint8_t g[] = {0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x4b, 0xad,
                                0x48, 0xcc, 0x2d, 0xc8, 0x49, 0xd5, 0x4b, 0xce, 0xcf, 0xe5, 0xd2, 0xd2,
                                0x4b, 0x85, 0xf2, 0xf2, 0x8b, 0xd2, 0xb9, 0xe2, 0x8a, 0x4b, 0x8a, 0x32,
                                0x93, 0x4b, 0x60, 0x62, 0x5c, 0x8a, 0xa9, 0x15, 0xa9, 0xb9, 0x05, 0x70,
                                0x3e, 0x58, 0x07, 0x00, 0x09, 0xec, 0x11, 0x29, 0x3e, 0x00, 0x00, 0x00};
    static const uint8_t raw[] = {0x4b, 0x4c, 0x4a, 0x4e, 0x44, 0x45, 0x0a, 0x19,
                                  0xa9, 0x39, 0x39, 0xf9, 0xc8, 0x24, 0x00};
    /* a stored block: BFINAL, BTYPE 00, LEN, NLEN, the bytes */
    static const uint8_t stored[] = {0x01, 0x05, 0x00, 0xfa, 0xff, 'h', 'e', 'l', 'l', 'o'};
    add(ud, z, sizeof(z));
    add(ud, g, sizeof(g));
    add(ud, raw, sizeof(raw));
    add(ud, stored, sizeof(stored));
}

/* ---- lists: host lists and IP sets -------------------------------------------- */

static void t_lists(const uint8_t *d, size_t n)
{
    static const char *const hosts[] = {"example.com", "www.example.com", "a.b.c.example.org", "com", "", "1.2.3.4",
                                        "strict.example", "x.strict.example"};
    xhostset hs;
    xipset is;
    char *text = text_of(d, n), bad[64], norm[256];
    size_t nbad = 0, first = 0;
    const char *nl;
    memset(&hs, 0, sizeof(hs));
    memset(&is, 0, sizeof(is));
    (void)xhs_parse(&hs, text, strlen(text));
    for (size_t i = 0; i < ARRAY_LEN(hosts); i++) {
        int ex = 0;
        (void)xhs_search(&hs, hosts[i], 0, &ex);
        (void)xhs_search(&hs, hosts[i], 1, &ex);
    }
    /* the first line as a name: once added, it is found */
    nl = strchr(text, '\n');
    first = nl ? (size_t)(nl - text) : strlen(text);
    if (first && first < 200) {
        char low[200];
        uint8_t fl = 0;
        for (size_t i = 0; i < first; i++)
            low[i] = (char)(text[i] >= 'A' && text[i] <= 'Z' ? text[i] + 32 : text[i]);
        if (xhs_add(&hs, low, first, 0) == 0)
            XFUZZ_CHECK(xhs_get(&hs, low, first, &fl));
    }
    (void)xips_parse(&is, text, strlen(text), &nbad, bad, sizeof(bad));
    xips_finish(&is);
    {
        uint8_t a4[4] = {10, 0, 0, 1}, a6[16] = {0x20, 0x01, 0x0d, 0xb8};
        (void)xips_has(&is, 4, a4);
        (void)xips_has(&is, 6, a6);
        if (n >= 16) {
            (void)xips_has(&is, 4, d);
            (void)xips_has(&is, 6, d);
        }
    }
    (void)xips_empty(&is);
    (void)xhost_norm(text, norm, sizeof(norm));
    xhs_free(&hs);
    xips_free(&is);
    free(text);
}

static void s_lists(xfuzz_add_fn add, void *ud)
{
    add_str(add, ud, "example.com\n*.example.org\n^strict.example\n!exempt.example.com\n# comment\n\n"
                     "  spaced.example  \r\nUPPER.Example.NET\n");
    add_str(add, ud, "1.2.3.4\n10.0.0.0/8\n192.168.0.0/16\n::1\n2a00::/16\n2001:db8::1/128\nbad\n 172.16.0.0/12\n");
    add_str(add, ud, "[2001:db8::1]:443");
}

/* ---- profile: the profile file of --ext-profile ------------------------------- */

static void t_profile(const uint8_t *d, size_t n)
{
    xprofiles ps;
    sbuf err;
    sb_init(&err);
    if (xprof_build_text((const char *)d, n > FUZZ_MAX ? FUZZ_MAX : n, &ps, &err) == 0) {
        xcapture c;
        uint8_t ip4[4] = {93, 184, 216, 34}, ip6[16] = {0x20, 0x01, 0x0d, 0xb8};
        xmatch m[] = {
            {4, 6, 443, 0, 0, L7_TLS, 0, ip4, "www.example.com", 0},
            {6, 17, 443, 0, 0, L7_QUIC, 0x20000000, ip6, NULL, 0},
            {4, 1, 0, 11, 0, L7_UNKNOWN, 0, ip4, NULL, 0},
            {4, 47, 0, 0, 0, L7_UNKNOWN, 0, ip4, "93.184.216.34", 1},
        };
        sb_reset(&err);
        (void)xprof_capture(&ps, 1, &c, &err);
        sb_reset(&err);
        (void)xprof_capture(&ps, 0, &c, &err);
        for (size_t i = 0; i < ARRAY_LEN(m); i++) {
            int k = xprof_find(&ps, &m[i], 0);
            XFUZZ_CHECK(k < (int)ps.n);
            (void)xprof_find(&ps, &m[i], 1);
        }
        for (size_t i = 0; i < ps.n; i++) {
            sb_reset(&err);
            xprof_label(ps.v[i], &err);
        }
        xprof_free(&ps);
    }
    sb_free(&err);
}

static void s_profile(xfuzz_add_fn add, void *ud)
{
    add_str(add, ud, "[template tls]\nfilter-tcp = 443\nfilter-l7 = tls\n\n[profile web]\nimport = tls\n"
                     "hostlist-domains = example.com,example.org\nstrategy = [TCP:flags:PA]-xsplit{pos=1}-| \\/\n");
    add_str(add, ud, "[profile]\nfilter-udp = 443,50000-50100\nfilter-l7 = quic\nfilter-l3 = ipv4,ipv6\n"
                     "ipset-ip = 10.0.0.0/8, 2001:db8::/32\nstrategy = [UDP:dport:443]-xfake{blob=fake_default_quic}-| \\/\n"
                     "[profile icmp]\nfilter-icmp = 3:4,11\nfilter-ipp = 47,50\nfilter-mark = 0x10/0xf0 # a comment\n"
                     "skip = 0\n[profile s]\nskip\nhostlist-exclude-domains = bad.example\n");
}

/* ---- spec: option values (markers, ranges, ports, filters, @FILE words) ------- */

static void t_spec(const uint8_t *d, size_t n)
{
    char *s = text_of(d, n);
    sbuf err, a, b;
    xmarker m[XMARKER_MAX];
    xrange r, r2;
    tls_modspec tm;
    uint8_t *blob = NULL;
    size_t blen = 0;
    uint64_t set;
    int neg, k;
    portset ps, ps2;
    sb_init(&err);
    sb_init(&a);
    sb_init(&b);
    /* markers: each prints back to itself */
    k = xmarker_list_parse(s, m, XMARKER_MAX, &err);
    for (int i = 0; i < k; i++) {
        xmarker m2;
        sb_reset(&a);
        xmarker_print(&m[i], &a);
        XFUZZ_CHECK(xmarker_parse(a.data, &m2) == 0);
        XFUZZ_CHECK(m2.pos == m[i].pos && m2.marker == m[i].marker);
    }
    /* ranges: the canonical form is stable */
    for (int dm = 0; dm < 2; dm++) {
        sb_reset(&err);
        if (xrange_parse(s, dm ? 'n' : 0, &r, &err) == 0) {
            sb_reset(&a);
            sb_reset(&b);
            xrange_print(&r, &a);
            XFUZZ_CHECK(xrange_parse(a.data, 0, &r2, &err) == 0);
            xrange_print(&r2, &b);
            XFUZZ_CHECK(!strcmp(a.data, b.data));
        }
    }
    (void)tls_mod_parse(s, &tm);
    if (blob_hex(s, 1 << 16, &blob, &blen) == 0)
        free(blob);
    (void)blob_name_ok(s);
    sb_reset(&err);
    (void)l7_payload_list(s, &set, &neg, &err);
    sb_reset(&err);
    (void)l7_proto_list(s, &set, &neg, &err);
    /* ports: what prints reads back the same */
    memset(&ps, 0, sizeof(ps));
    if (ports_parse(s, &ps) == 0) {
        sb_reset(&a);
        ports_format(&ps, &a, ",", "-");
        memset(&ps2, 0, sizeof(ps2));
        XFUZZ_CHECK(ports_parse(a.data, &ps2) == 0);
        for (int p = 0; p < 65536; p += 7)
            XFUZZ_CHECK(ports_has(&ps, (uint16_t)p) == ports_has(&ps2, (uint16_t)p));
    }
    {
        xpf *pf = NULL;
        xicf *icf = NULL;
        xipp *ipp = NULL;
        size_t c = 0;
        uint32_t mk, mm;
        /* (the arrays stay the caller's when a later item is bad) */
        (void)xprof_pf_list(s, &pf, &c);
        free(pf);
        c = 0;
        (void)xprof_icf_list(s, &icf, &c);
        free(icf);
        c = 0;
        (void)xprof_ipp_list(s, &ipp, &c);
        free(ipp);
        (void)xprof_mark(s, &mk, &mm);
    }
    {
        fw_config c;
        char buf[256];
        const char *v[FW_MAX_IFS];
        ct_config ct;
        uint16_t tf;
        uint8_t ipf;
        char out[32];
        log_level lv;
        memset(&c, 0, sizeof(c));
        (void)xfw_first(s, 0, &c);
        (void)xfw_iflist(s, buf, sizeof(buf), v);
        ct_config_default(&ct);
        (void)ct_timeouts_parse(s, &ct);
        if (tcp_flags_parse(s, &tf) == 0) {
            uint16_t tf2;
            tcp_flags_str(tf, out);
            XFUZZ_CHECK(tcp_flags_parse(out, &tf2) == 0 && tf2 == tf);
        }
        if (ip_flags_parse(s, &ipf) == 0)
            ip_flags_str(ipf, out);
        (void)log_parse_level(s, &lv);
    }
    {
        char **w = NULL;
        sb_reset(&err);
        if (xcfg_split((const char *)d, n > FUZZ_MAX ? FUZZ_MAX : n, &w, &err) >= 0)
            xcfg_free(w);
    }
    sb_free(&err);
    sb_free(&a);
    sb_free(&b);
    free(s);
}

static void s_spec(xfuzz_add_fn add, void *ud)
{
    static const char *const v[] = {"1,host,midsld,endhost-1,sniext+1,method+2,-5",
                                    "n1-n5",
                                    "s1-s100000<",
                                    "d2-a",
                                    "x",
                                    "rnd,rndsni,sni=a.example,dupsid,padencap,none",
                                    "0x16030100ff",
                                    "tls_client_hello,http_req,~quic_initial",
                                    "~tls,http,quic,known,unknown",
                                    "80,443,8000-8100,1:5",
                                    "~0-79,*,3:4,11",
                                    "0x20000000/0xf0000000",
                                    "tcp-out=4,udp-in=2,in=1",
                                    "eth0,ppp1,wg0",
                                    "60:300:60:60",
                                    "SA",
                                    "MF+DF",
                                    "debug",
                                    "--filter-tcp=443 \"quoted words\" 'single' \\\\escaped ${HOME} # comment",
                                    NULL};
    for (int i = 0; v[i]; i++)
        add_str(add, ud, v[i]);
}

/* ---- the table ------------------------------------------------------------------- */

static const xfuzz_target targets[] = {
    {"pkt", "Geneva's packet reader, its fields and tampers", t_pkt, s_pkt},
    {"strategy", "the strategy language with the x-actions; prints back the same", t_strategy, s_strategy},
    {"apply", "packets through the strategies with conntrack and reassembly (geneva apply --ext)", t_apply, s_apply},
    {"pcap", "the pcap and pcapng reader", t_pcap, s_pcap},
    {"json", "JSON of the control socket and lines of the strategy database", t_json, s_json},
    {"l7", "payload recognition, host names and position markers", t_l7, s_l7},
    {"tls", "TLS SNI, tls_mod and the ClientHello clone", t_tls, s_tls},
    {"quic", "QUIC Initial header, decryption and CRYPTO frames", t_quic, s_quic},
    {"inflate", "gzip, zlib and raw DEFLATE of the list files", t_inflate, s_inflate},
    {"lists", "host lists and IP sets", t_lists, s_lists},
    {"profile", "the profile file of --ext-profile", t_profile, s_profile},
    {"spec", "option values: markers, ranges, ports, filters, @FILE words", t_spec, s_spec},
};

const xfuzz_target *xfuzz_targets(size_t *n)
{
    *n = ARRAY_LEN(targets);
    return targets;
}

const xfuzz_target *xfuzz_find(const char *name)
{
    for (size_t i = 0; i < ARRAY_LEN(targets); i++)
        if (!strcmp(targets[i].name, name))
            return &targets[i];
    return NULL;
}

void xfuzz_init(void)
{
    static const optdef defs[] = {{"ext", 0, 0, NULL, NULL}, {NULL, 0, 0, NULL, NULL}};
    char *argv[] = {"fuzz", "--ext", NULL};
    args_t a;
    char err[128];
    log_set_quiet(1);
    log_set_level(LOG_ERROR);
    if (args_parse(&a, 2, argv, defs, err, sizeof(err)) < 0 || ext_parse_args(&a, "fuzz") < 0)
        xfuzz_fail("--ext", __FILE__, __LINE__);
    args_free(&a);
}

void xfuzz_run(const xfuzz_target *t, const uint8_t *d, size_t n)
{
    rng_global_seed(1);
    t->run(d, n);
}

/* ---- the mutator --------------------------------------------------------------- */

uint64_t xfuzz_rand(uint64_t *rs)
{
    /* splitmix64 */
    uint64_t z = (*rs += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static size_t below(uint64_t *rs, size_t n)
{
    return n ? (size_t)(xfuzz_rand(rs) % n) : 0;
}

size_t xfuzz_mutate(uint8_t *d, size_t n, size_t cap, uint64_t *rs, const uint8_t *other, size_t on)
{
    static const uint8_t interesting[] = {0, 1, 0x7f, 0x80, 0xff, 0xfe, 0x40, 0x20, 0x16, 0x03, '\n', ',', '=',
                                          ';', '{', '}', '(', ')', '[', ']', ':', '-', '|', '\\', '/', '.'};
    int rounds = 1 + (int)below(rs, 4);
    for (int k = 0; k < rounds; k++) {
        size_t at = below(rs, n + 1), len;
        switch (below(rs, 9)) {
        case 0: /* a bit */
            if (n)
                d[below(rs, n)] ^= (uint8_t)(1u << below(rs, 8));
            break;
        case 1: /* a byte */
            if (n)
                d[below(rs, n)] = (uint8_t)xfuzz_rand(rs);
            break;
        case 2: /* an interesting byte */
            if (n)
                d[below(rs, n)] = interesting[below(rs, sizeof(interesting))];
            break;
        case 3: /* a 16-bit length or count, big endian */
            if (n >= 2) {
                size_t p = below(rs, n - 1);
                static const uint16_t v[] = {0, 1, 0x7f, 0x80, 0xff, 0x100, 0x3fff, 0x4000, 0x7fff, 0xffff};
                uint16_t x = v[below(rs, ARRAY_LEN(v))];
                d[p] = (uint8_t)(x >> 8);
                d[p + 1] = (uint8_t)x;
            }
            break;
        case 4: /* delete a run */
            if (n) {
                len = 1 + below(rs, n - at < 16 ? n - at + 1 : 16);
                if (at + len > n)
                    len = n - at;
                memmove(d + at, d + at + len, n - at - len);
                n -= len;
            }
            break;
        case 5: /* insert random bytes */
            len = 1 + below(rs, 16);
            if (n + len <= cap) {
                memmove(d + at + len, d + at, n - at);
                for (size_t i = 0; i < len; i++)
                    d[at + i] = (uint8_t)xfuzz_rand(rs);
                n += len;
            }
            break;
        case 6: /* copy a run of d elsewhere in d (overwrite) */
            if (n >= 2) {
                size_t from = below(rs, n), to = below(rs, n);
                len = 1 + below(rs, 32);
                if (from + len > n)
                    len = n - from;
                if (to + len > n)
                    len = n - to;
                memmove(d + to, d + from, len);
            }
            break;
        case 7: /* splice: a run of other inserted */
            if (other && on) {
                size_t from = below(rs, on);
                len = 1 + below(rs, 64);
                if (from + len > on)
                    len = on - from;
                if (n + len <= cap) {
                    memmove(d + at + len, d + at, n - at);
                    memcpy(d + at, other + from, len);
                    n += len;
                }
            }
            break;
        default: /* truncate */
            if (n)
                n = at;
            break;
        }
    }
    return n;
}
