/*
 * The genetic operators for x-actions (docs/EVOLVE.md, "x-действия"):
 * geneva evolve --ext makes new x-actions and changes the parameters of the
 * ones it has, as Geneva's mutate does for tamper and fragment. The values
 * are the ones zapret2's strategies and blockcheck2 use (markers, TTLs,
 * foolings, blobs, repeats, ...), drawn at random.
 *
 * A changed action is written as text and parsed again by xa_parse(), so
 * it passes the same checks as one a person writes; what the checks refuse
 * is drawn again.
 *
 * Every action that changes what a censor sees is made, with every key it
 * takes; tests/test_xgen.c (xgen_coverage) checks that. Left out: xlog and
 * xpcap (they only log), the obfuscators (xwgobfs, xippxor, xudp2icmp,
 * xsynhide: the other end has to undo them), and the keys of the host's own
 * setup (ifout, fwmark) or of other protocols (ipfrag_pos_icmp, ipfrag_pos).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "blob.h"
#include "rng.h"
#include "xact.h"

/* ---- the actions the operators make ------------------------------------------- */

typedef struct {
    const char *name;
    unsigned char tcp, udp; /* transports it acts on */
    unsigned char out, in;  /* forests it is made in on the client */
    unsigned char sout;     /* made in the server's outbound forest (evolve
                             * --agent: the strategy runs on the server; its
                             * inbound forest gets none) */
    unsigned char fool;     /* sends fakes: the fooling that breaks a packet (TTL,
                             * seq, md5, badsum, ...) is drawn; not for the real data */
    unsigned char w;        /* weight among new ones; 0: never made, only changed */
    const char *req;        /* keys a new one gets, ";"-separated */
} gkind;

/* xwsize changes the server's SYN,ACK: made in the client's inbound forest
 * or in the server's outbound one. xsynacksplit, too, splits the server's
 * SYN,ACK. The names xtlsclone and xtag give their blob and label are
 * the ones the other actions draw now and then (GEN_CLONE, GEN_TAG). */
static const gkind gkinds[] = {
    {"xfake", 1, 1, 1, 0, 1, 1, 8, "blob"},
    {"xsplit", 1, 0, 1, 0, 1, 0, 5, "pos"},
    {"xdisorder", 1, 0, 1, 0, 1, 0, 5, "pos"},
    {"xfakedsplit", 1, 0, 1, 0, 1, 1, 3, "pos"},
    {"xfakeddisorder", 1, 0, 1, 0, 1, 1, 3, "pos"},
    {"xtcpseg", 1, 0, 1, 0, 1, 0, 2, "pos"},
    {"xhostfake", 1, 0, 1, 0, 0, 1, 2, ""},
    {"xtlsrec", 1, 0, 1, 0, 1, 0, 2, "pos"},
    {"xoob", 1, 0, 1, 0, 1, 0, 1, "urp"},
    {"xdrip", 1, 0, 1, 0, 1, 0, 1, "n"},
    {"xrst", 1, 0, 1, 0, 1, 1, 1, ""},
    {"xsyndata", 1, 0, 1, 0, 0, 1, 1, ""},
    {"xsynack", 1, 0, 1, 0, 0, 1, 1, ""},
    {"xwssize", 1, 0, 1, 0, 0, 0, 1, "wsize;scale"},
    {"xwsize", 1, 0, 0, 1, 1, 0, 1, "wsize;scale"},
    {"xsynacksplit", 1, 0, 0, 0, 1, 0, 1, "mode"},
    {"xhttp", 1, 0, 1, 0, 0, 0, 1, "hostcase"},
    {"xtlsclone", 1, 0, 1, 0, 0, 0, 1, "blob"},
    {"xtag", 1, 1, 1, 0, 1, 0, 1, "pattern;payload"},
    {"xsend", 1, 1, 1, 0, 1, 0, 2, "ipfrag"},
    {"xmod", 1, 1, 1, 0, 1, 0, 1, "ipid"},
    {"xudplen", 0, 1, 1, 0, 1, 0, 2, "increment"},
    {"xdhtdn", 0, 1, 1, 0, 1, 0, 1, "dn"},
    {"xrepeat", 1, 1, 1, 0, 1, 0, 1, "repeats"},
    {"xwhen", 1, 1, 1, 0, 1, 0, 1, "iff"},
    {"xstop", 1, 1, 1, 0, 1, 0, 1, "iff"},
    {"xcutoff", 1, 1, 1, 0, 1, 0, 1, ""},
};

#define GEN_CLONE "gclone" /* xtlsclone's blob */
#define GEN_TAG "gtag"     /* xtag's labels: GEN_TAG and GEN_TAG "_no" */

static const gkind *gkind_of(const char *name)
{
    for (size_t i = 0; i < ARRAY_LEN(gkinds); i++)
        if (!strcmp(gkinds[i].name, name))
            return &gkinds[i];
    return NULL;
}

static int fits(const gkind *k, const strat_xgen *g)
{
    int forest = g->server ? g->dir == DIR_OUT && k->sout : g->dir == DIR_IN ? k->in : k->out;
    if (!k->w || !forest || !((k->tcp && g->tcp) || (k->udp && g->udp)))
        return 0;
    return !g->skip || !*g->skip || !xa_in_list(g->skip, k->name);
}

/* ---- parameters ------------------------------------------------------------------ */

#define GP_MAX 24

typedef struct {
    char *k;
    char *v; /* NULL: a flag */
} gparam;

typedef struct {
    gparam p[GP_MAX];
    int n;
} plist;

static void pl_free(plist *l)
{
    for (int i = 0; i < l->n; i++) {
        free(l->p[i].k);
        free(l->p[i].v);
    }
    l->n = 0;
}

static int pl_find(const plist *l, const char *k)
{
    for (int i = 0; i < l->n; i++)
        if (!strcmp(l->p[i].k, k))
            return i;
    return -1;
}

static void pl_del(plist *l, int i)
{
    free(l->p[i].k);
    free(l->p[i].v);
    memmove(&l->p[i], &l->p[i + 1], (size_t)(l->n - i - 1) * sizeof(l->p[0]));
    l->n--;
}

static void pl_set(plist *l, const char *k, char *v)
{
    int i = pl_find(l, k);
    if (i >= 0) {
        free(l->p[i].v);
        l->p[i].v = v;
        return;
    }
    if (l->n == GP_MAX) {
        free(v);
        return;
    }
    l->p[l->n].k = xstrdup(k);
    l->p[l->n].v = v;
    l->n++;
}

/* "k=v;k2" or NULL without parameters (no braces) */
static char *pl_text(const plist *l)
{
    sbuf b;
    if (!l->n)
        return NULL;
    sb_init(&b);
    for (int i = 0; i < l->n; i++) {
        if (i)
            sb_putc(&b, ';');
        sb_puts(&b, l->p[i].k);
        if (l->p[i].v)
            sb_printf(&b, "=%s", l->p[i].v);
    }
    return sb_take(&b);
}

/* ---- values ------------------------------------------------------------------------- */

static const char *pick(const char *const *v, size_t n) { return v[rng_index(n)]; }
#define PICK(arr) pick(arr, ARRAY_LEN(arr))

/* a blob that fits the transports: a TLS record or an HTTP request for TCP,
 * the rest for UDP; the default fakes come up more often */
static int blob_tcp(const xblob *b)
{
    const uint8_t *d = b->data;
    size_t i = 0;
    if (b->len >= 2 && d[0] == 0x16 && d[1] == 0x03)
        return 1;
    while (i < b->len && i < 8 && d[i] >= 'A' && d[i] <= 'Z')
        i++;
    return i >= 3 && i < b->len && d[i] == ' ';
}

/* the canonical keys that break the packet they are on: TTLs, IPv6 extension
 * headers, seq, ack, ts, md5, flags, badsum (only fakes get them) */
static int breaking(const char *k)
{
    static const char *const b[] = {"ttl", "ip_ttl", "ip_autottl", "seq", "ack", "ts", "md5", "flags+", "flags-",
                                    "badsum", "ip6ext"};
    for (size_t i = 0; i < ARRAY_LEN(b); i++)
        if (!strcmp(k, b[i]))
            return 1;
    return !strncmp(k, "ip6_", 4);
}

/* the keys that change TCP headers: never drawn for a tree of UDP only */
static int tcp_only(const char *k)
{
    static const char *const t[] = {"seq", "ack", "ts", "md5", "flags+", "flags-", "tsup", "nopdel"};
    for (size_t i = 0; i < ARRAY_LEN(t); i++)
        if (!strcmp(k, t[i]))
            return 1;
    return 0;
}

static void gen_blob(const strat_xgen *g, sbuf *v)
{
    const char *names[256];
    size_t n = 0;
    const xblob *b;
    const char *nm;
    if (rng_chance(0.4)) {
        static const char *const tcp[] = {"fake_default_tls", "fake_default_tls", "fake_default_http"};
        static const char *const udp[] = {"fake_quic_initial", "fake_default_quic"};
        const char *d = g->tcp && (!g->udp || rng_chance(0.5)) ? PICK(tcp) : PICK(udp);
        if (blob_find(d)) {
            sb_puts(v, d);
            return;
        }
    }
    if (g->tcp && !g->server && rng_chance(0.05)) {
        sb_puts(v, GEN_CLONE); /* the ClientHello an xtlsclone before made */
        return;
    }
    for (size_t i = 0; n < ARRAY_LEN(names) && (nm = blob_name_at(i, &b)); i++) {
        int t = blob_tcp(b);
        if ((t && g->tcp) || (!t && g->udp))
            names[n++] = nm;
    }
    if (!n || rng_chance(0.1)) {
        /* a few bytes of one value, as the zero fakes of zapret2's UDP lines */
        int len = (int)rng_range(1, 64), byte = rng_chance(0.5) ? 0 : (int)rng_range(0, 255);
        sb_puts(v, "0x");
        for (int i = 0; i < len; i++)
            sb_printf(v, "%02x", byte);
        return;
    }
    sb_puts(v, names[rng_index(n)]);
}

/* n random bytes as 0x... */
static void gen_hex(sbuf *v, int n)
{
    sb_puts(v, "0x");
    for (int i = 0; i < n; i++)
        sb_printf(v, "%02x", (unsigned)rng_range(0, 255));
}

/* a position marker: a number (from the end when negative) or a named
 * place with an offset */
static void gen_marker(sbuf *v, int tls)
{
    static const char *const names[] = {"host", "endhost", "sld", "midsld", "endsld", "method", "extlen", "sniext"};
    static const char *const tlsn[] = {"host", "endhost", "sld", "midsld", "endsld", "extlen", "sniext"};
    if (rng_chance(0.4)) {
        static const int small[] = {1, 2, 3, 4, 5, 6, 8, 10, 16, 32};
        int n = rng_chance(0.8) ? small[rng_index(ARRAY_LEN(small))] : (int)rng_range(1, 400);
        sb_printf(v, "%d", rng_chance(0.1) ? -n : n);
        return;
    }
    sb_puts(v, tls ? PICK(tlsn) : PICK(names));
    if (rng_chance(0.3)) {
        int d = (int)rng_range(-2, 4);
        if (d)
            sb_printf(v, "%+d", d);
    }
}

static void gen_markers(sbuf *v, int n, int tls)
{
    for (int i = 0; i < n; i++) {
        if (i)
            sb_putc(v, ',');
        gen_marker(v, tls);
    }
}

static const char *const snis[] = {"www.google.com", "www.microsoft.com", "yandex.ru", "vk.com", "www.iana.org",
                                   "example.com"};

/* a host name: a well-known one or a few random letters */
static void gen_host(sbuf *v)
{
    if (rng_chance(0.7)) {
        sb_puts(v, PICK(snis));
        return;
    }
    for (int i = 0, n = (int)rng_range(3, 12); i < n; i++)
        sb_putc(v, (char)('a' + rng_index(26)));
    sb_puts(v, rng_chance(0.5) ? ".com" : ".ru");
}

static void gen_tlsmod(sbuf *v)
{
    static const char *const mods[] = {"rnd", "rndsni", "dupsid", "padencap"};
    int any = 0;
    if (rng_chance(0.05)) {
        sb_puts(v, "none");
        return;
    }
    for (size_t i = 0; i < ARRAY_LEN(mods); i++)
        if (rng_chance(0.35)) {
            sb_printf(v, "%s%s", any ? "," : "", mods[i]);
            any = 1;
        }
    if (!any || rng_chance(0.2)) {
        sb_printf(v, "%ssni=", any ? "," : "");
        gen_host(v);
    }
}

static void gen_flags(sbuf *v)
{
    static const char *const fl[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    size_t a = rng_index(ARRAY_LEN(fl)), b = rng_index(ARRAY_LEN(fl));
    sb_puts(v, fl[a]);
    if (b != a && rng_chance(0.3))
        sb_printf(v, ",%s", fl[b]);
}

/* an IPv6 extension header's data: 6+8N bytes (6+4N for AH) */
static void gen_ext6_data(sbuf *v, int ah) { gen_hex(v, 6 + (ah ? 4 : 8) * (int)rng_range(0, 2)); }

static void gen_ip6ext(sbuf *v)
{
    static const char *const ext[] = {"hopbyhop", "hopbyhop2", "destopt", "destopt2", "routing", "ah"};
    size_t a = rng_index(ARRAY_LEN(ext)), b = rng_index(ARRAY_LEN(ext));
    sb_puts(v, ext[a]);
    if (rng_chance(0.15))
        sb_putc(v, ':'), gen_ext6_data(v, a == 5);
    if (b != a && rng_chance(0.3))
        sb_printf(v, ",%s", ext[b]);
}

/* payload types (zapret2's names) of the transports, or the label xtag sets */
static void gen_payload(const strat_xgen *g, sbuf *v)
{
    static const char *const tcp[] = {"tls_client_hello", "http_req",        "xmpp_stream",   "xmpp_starttls",
                                      "mtproto_initial",  "bt_handshake",    "empty",         "unknown"};
    static const char *const tcp_srv[] = {"tls_server_hello", "http_reply", "xmpp_proceed", "xmpp_features",
                                          "empty", "unknown"};
    static const char *const udp[] = {"quic_initial",         "dtls_client_hello",   "wireguard_initiation",
                                      "wireguard_cookie",     "wireguard_keepalive", "wireguard_data",
                                      "dht",                  "discord_ip_discovery", "stun",
                                      "dns_query",            "utp_bt_handshake",    "unknown"};
    static const char *const udp_srv[] = {"dtls_server_hello", "wireguard_response", "dns_response", "stun",
                                          "unknown"};
    static const char *const any[] = {"known", "all"};
    double r = rng_real();
    if (rng_chance(0.1))
        sb_putc(v, '~');
    if (r < 0.05)
        sb_puts(v, rng_chance(0.5) ? GEN_TAG : GEN_TAG "_no");
    else if (r < 0.45 && g->tcp && (!g->udp || rng_chance(0.5)))
        sb_puts(v, g->server ? PICK(tcp_srv) : PICK(tcp));
    else if (r < 0.45 && g->udp)
        sb_puts(v, g->server ? PICK(udp_srv) : PICK(udp));
    else
        sb_puts(v, PICK(any));
}

/* a condition of xwhen, xstop, xrepeat: zapret2's cond_* or a trigger */
static const char *gen_iff(const strat_xgen *g, sbuf *v)
{
    static const char *const conds[] = {"cond_random", "cond_payload_str", "cond_true", "cond_false",
                                        "cond_tcp_has_ts"};
    static const char *const protos[] = {"tls", "http", "quic", "dtls", "wireguard", "dht", "discord",
                                         "stun", "xmpp", "dns", "mtproto", "bt", "utp_bt", "known", "unknown"};
    static const char *const flags[] = {"PA", "A", "S", "SA", "FA", "R"};
    int r = (int)rng_index(5);
    const char *c;
    if (r == 0) {
        c = PICK(conds);
        if (!strcmp(c, "cond_tcp_has_ts") && !g->tcp)
            c = "cond_random";
        sb_puts(v, c);
        return c;
    }
    if (r == 1) {
        sb_puts(v, "L7:payload:");
        gen_payload(g, v);
    } else if (r == 2) {
        sb_printf(v, "L7:proto:%s%s", rng_chance(0.1) ? "~" : "", PICK(protos));
    } else if (r == 3) {
        static const char *const fields[] = {"n", "d", "b", "s", "p", "rn", "rd"};
        const char *f = PICK(fields);
        int b = !strcmp(f, "b") || !strcmp(f, "s") || !strcmp(f, "p");
        int hi = b ? (int)rng_range(100, 4000) : (int)rng_range(1, 10);
        int kind = (int)rng_index(3);
        if (kind == 0)
            sb_printf(v, "FLOW:%s:<%d", f, hi);
        else if (kind == 1)
            sb_printf(v, "FLOW:%s:%d", f, b ? hi : (int)rng_range(1, 5));
        else
            sb_printf(v, "FLOW:%s:%d-%d", f, b ? 0 : 1, hi);
    } else if (g->tcp && rng_chance(0.7)) {
        sb_printf(v, "TCP:flags:%s", PICK(flags));
    } else {
        static const char *const st[] = {"syn", "est", "fin"};
        if (g->tcp && rng_chance(0.5))
            sb_printf(v, "FLOW:state:%s", PICK(st));
        else
            sb_puts(v, "FLOW:retrans:1");
    }
    return "";
}

/* what cond_payload_str and xtag look for (no spaces in a strategy) */
static void gen_pattern_str(sbuf *v)
{
    static const char *const s[] = {"GET",     "POST",     "Host:",   "HTTP/1.", "google",
                                    "youtube", "discord", "telegram", "Blocked"};
    sb_puts(v, PICK(s));
}

static int64_t gen_offset(const int64_t *common, size_t n, int64_t lo, int64_t hi)
{
    return rng_chance(0.7) ? common[rng_index(n)] : rng_range(lo, hi);
}

static int is_comb(const char *kind) { return !strcmp(kind, "xwhen") || !strcmp(kind, "xstop") || !strcmp(kind, "xrepeat"); }

/* Draws a value of key for an action named kind. Returns 1 with the value
 * in v, 0 for a flag (no value), -1 when the key is never drawn (files,
 * interfaces, marks: the host's own setup). */
static int gen_value(const char *kind, const char *key, const strat_xgen *g, sbuf *v)
{
    static const char *const flags[] = {"badsum",  "tsup",    "nopdel",  "ipid_conn", "ipfrag_disorder", "optional",
                                        "nodrop",  "legacy",  "nofake1", "nofake2",   "nofake3",         "nofake4",
                                        "rstack",  "neg",     "domcase", "methodeol", "unixeol",         "stop",
                                        "clear",   "sni_del_ext", "sni_del"};
    int tls = g->tcp && !strcmp(kind, "xtlsrec");
    if (!g->tcp && tcp_only(key))
        return -1;
    for (size_t i = 0; i < ARRAY_LEN(flags); i++)
        if (!strcmp(key, flags[i]))
            return 0;
    if (!strcmp(key, "ttl")) {
        if (rng_chance(0.6)) {
            sb_printf(v, "%d", (int)rng_range(1, 12));
        } else {
            static const int mx[] = {12, 16, 20, 32, 64};
            sb_printf(v, "auto:%d:%d-%d", -(int)rng_range(1, 4), (int)rng_range(1, 5), mx[rng_index(ARRAY_LEN(mx))]);
        }
    } else if (!strcmp(key, "ip_ttl") || !strcmp(key, "ip6_ttl")) {
        sb_printf(v, "%d", (int)rng_range(1, 12));
    } else if (!strcmp(key, "ip_autottl") || !strcmp(key, "ip6_autottl")) {
        static const int mx[] = {12, 16, 20, 32, 64};
        sb_printf(v, "%d,%d-%d", -(int)rng_range(1, 4), (int)rng_range(1, 5), mx[rng_index(ARRAY_LEN(mx))]);
    } else if (!strncmp(key, "ip6_", 4)) {
        /* ip6_hopbyhop, ..., ip6_ah: the header, empty or with data */
        if (rng_chance(0.7))
            return 0;
        gen_ext6_data(v, !strcmp(key, "ip6_ah"));
    } else if (!strcmp(key, "md5")) {
        if (rng_chance(0.8))
            return 0;
        gen_hex(v, 16);
    } else if (!strcmp(key, "ipfrag")) {
        if (rng_chance(0.7))
            return 0;
        sb_puts(v, "ipfrag2");
    } else if (!strcmp(key, "ipfrag_next")) {
        static const int nh[] = {0, 6, 17, 41, 44, 58, 59, 255};
        sb_printf(v, "%d", nh[rng_index(ARRAY_LEN(nh))]);
    } else if (!strcmp(key, "seq") || !strcmp(key, "ack")) {
        static const int64_t c[] = {1, 100, 1000, 10000, 66000, 100000, 1000000};
        int64_t n = gen_offset(c, ARRAY_LEN(c), 1, 1 << 24);
        sb_printf(v, "%lld", (long long)(rng_chance(0.85) ? -n : n));
    } else if (!strcmp(key, "ts")) {
        static const int64_t c[] = {1000, 60000, 600000, 6000000};
        sb_printf(v, "%lld", -(long long)gen_offset(c, ARRAY_LEN(c), 1, 10000000));
    } else if (!strcmp(key, "flags+") || !strcmp(key, "flags-")) {
        gen_flags(v);
    } else if (!strcmp(key, "repeats")) {
        if (!strcmp(kind, "xrepeat"))
            sb_printf(v, "%d", (int)rng_range(2, 6));
        else
            sb_printf(v, "%d", rng_chance(0.7) ? (int)rng_range(1, 6) : (int)rng_range(7, 20));
    } else if (!strcmp(key, "ipid")) {
        static const char *const ids[] = {"seq", "rnd", "zero", "none"};
        sb_puts(v, PICK(ids));
    } else if (!strcmp(key, "ipfrag_pos_tcp")) {
        if (!g->tcp)
            return -1;
        sb_printf(v, "%d", 8 * (int)rng_range(1, 8));
    } else if (!strcmp(key, "ipfrag_pos_udp")) {
        if (!g->udp)
            return -1;
        sb_printf(v, "%d", 8 * (int)rng_range(1, 4));
    } else if (!strcmp(key, "ip6ext")) {
        gen_ip6ext(v);
    } else if (!strcmp(key, "payload")) {
        if (!strcmp(kind, "xtag"))
            sb_puts(v, GEN_TAG); /* the label it sets */
        else
            gen_payload(g, v);
    } else if (!strcmp(key, "undetected")) {
        sb_puts(v, GEN_TAG "_no");
    } else if (!strcmp(key, "forced_cutoff")) {
        static const char *const fc[] = {"tls_client_hello", "http_req", "known", "tls_client_hello,http_req"};
        sb_puts(v, PICK(fc));
    } else if (!strcmp(key, "pos")) {
        if (!strcmp(kind, "xtcpseg")) {
            if (rng_chance(0.5))
                sb_puts(v, "0,");
            else
                gen_marker(v, 0), sb_putc(v, ',');
            gen_marker(v, 0);
        } else if (!strcmp(kind, "xfakedsplit") || !strcmp(kind, "xfakeddisorder") || !strcmp(kind, "xtlsrec")) {
            gen_marker(v, tls);
        } else {
            gen_markers(v, rng_chance(0.6) ? 1 : (int)rng_range(2, 4), 0);
        }
    } else if (!strcmp(key, "midhost") || !strcmp(key, "disorder_after")) {
        gen_marker(v, 0);
    } else if (!strcmp(key, "host")) {
        gen_host(v);
    } else if (!strcmp(key, "seqovl")) {
        static const int64_t c[] = {1, 2, 5, 10, 100, 336, 568, 652};
        sb_printf(v, "%lld", (long long)gen_offset(c, ARRAY_LEN(c), 1, 700));
    } else if (!strcmp(key, "pattern") && (is_comb(kind) || !strcmp(kind, "xtag"))) {
        gen_pattern_str(v); /* cond_payload_str's text, xtag's */
    } else if (!strcmp(key, "blob") && !strcmp(kind, "xtlsclone")) {
        sb_puts(v, GEN_CLONE);
    } else if (!strcmp(key, "blob") || !strcmp(key, "pattern") || !strcmp(key, "seqovl_pattern") ||
               !strcmp(key, "fallback")) {
        gen_blob(g, v);
    } else if (!strcmp(key, "sni_snt") || !strcmp(key, "sni_snt_new")) {
        sb_printf(v, "%d", rng_chance(0.7) ? 0 : (int)rng_range(1, 255));
    } else if (!strcmp(key, "sni_first") || !strcmp(key, "sni_last")) {
        gen_host(v);
    } else if (!strcmp(key, "tlsmod")) {
        gen_tlsmod(v);
    } else if (!strcmp(key, "urp")) {
        if (rng_chance(0.4))
            sb_puts(v, rng_chance(0.7) ? "b" : "e");
        else
            gen_marker(v, 0);
    } else if (!strcmp(key, "char")) {
        sb_printf(v, "%c", (char)('a' + rng_index(26)));
    } else if (!strcmp(key, "byte")) {
        sb_printf(v, "%d", (int)rng_range(0, 255));
    } else if (!strcmp(key, "n")) {
        sb_printf(v, "%d", (int)rng_range(2, 16));
    } else if (!strcmp(key, "delay")) {
        /* xdrip's pause between the parts; xsend's holds the packet, so short */
        sb_printf(v, "%d", strcmp(kind, "xdrip") ? (int)rng_range(1, 20) : (int)rng_range(0, 100));
    } else if (!strcmp(key, "wsize")) {
        sb_printf(v, "%d", rng_chance(0.7) ? (int)rng_range(1, 64) : (int)rng_range(65, 4096));
    } else if (!strcmp(key, "scale")) {
        sb_printf(v, "%d", (int)rng_range(0, 14));
    } else if (!strcmp(key, "hostcase")) {
        char h[5] = "host";
        if (rng_chance(0.5))
            return 0;
        for (int i = 0; i < 4; i++)
            if (rng_chance(0.5))
                h[i] = (char)(h[i] - 'a' + 'A');
        sb_puts(v, h);
    } else if (!strcmp(key, "increment")) {
        int64_t n = rng_range(1, 64);
        sb_printf(v, "%lld", (long long)(rng_chance(0.8) ? n : -n));
    } else if (!strcmp(key, "min")) {
        sb_printf(v, "%d", (int)rng_range(64, 1200));
    } else if (!strcmp(key, "max")) {
        sb_printf(v, "%d", (int)rng_range(1200, 1500));
    } else if (!strcmp(key, "pattern_offset")) {
        sb_printf(v, "%d", (int)rng_range(0, 64));
    } else if (!strcmp(key, "dn")) {
        sb_printf(v, "%d", (int)rng_range(1, 10));
    } else if (!strcmp(key, "dir")) {
        static const char *const d[] = {"in", "out", "both"};
        sb_puts(v, PICK(d));
    } else if (!strcmp(key, "iff")) {
        gen_iff(g, v);
    } else if (!strcmp(key, "percent")) {
        sb_printf(v, "%d", (int)rng_range(1, 99));
    } else if (!strcmp(key, "mode")) {
        static const char *const m[] = {"syn", "synack", "acksyn"};
        sb_puts(v, PICK(m));
    } else {
        return -1;
    }
    return 1;
}

/* the common arguments a search draws (not: ifout, fwmark, the host's own;
 * ipfrag_pos_icmp, ipfrag_pos, for packets the trees never see); the
 * breaking() ones only fakes get */
static const char *const std_drawn[] = {
    "ttl",          "ip_ttl",        "ip6_ttl",     "ip_autottl",    "ip6_autottl",   "seq",
    "ack",          "ts",            "md5",         "flags+",        "flags-",        "badsum",
    "ip6ext",       "ip6_hopbyhop",  "ip6_hopbyhop2", "ip6_destopt", "ip6_destopt2",  "ip6_routing",
    "ip6_ah",       "tsup",          "nopdel",      "repeats",       "ipid",          "ipid_conn",
    "ipfrag",       "ipfrag_disorder", "ipfrag_pos_tcp", "ipfrag_pos_udp", "ipfrag_next", "payload"};

/* the keys of k that can be drawn, as k takes them */
static int drawable_keys(const xa_kind *k, const gkind *gk, const char **out, int max)
{
    int n = 0;
    for (size_t i = 0; i < ARRAY_LEN(std_drawn) && n < max; i++)
        if ((gk->fool || !breaking(std_drawn[i])) && xa_canon_key(k, std_drawn[i]))
            out[n++] = std_drawn[i];
    for (int i = 0; k->keys && k->keys[i] && n < max; i++)
        out[n++] = k->keys[i];
    return n;
}

/* the keys of a condition go together: cond_payload_str needs pattern, only
 * cond_random takes percent */
static void cond_couple(const xa_kind *k, const char *key, const strat_xgen *g, plist *l)
{
    int i = pl_find(l, "iff");
    const char *iff = i >= 0 ? l->p[i].v : NULL;
    if (!is_comb(k->name))
        return;
    if (!strcmp(key, "pattern") || !strcmp(key, "percent")) {
        pl_set(l, "iff", xstrdup(key[1] == 'a' ? "cond_payload_str" : "cond_random"));
        iff = key[1] == 'a' ? "cond_payload_str" : "cond_random";
    }
    if (!iff)
        return;
    if (strcmp(iff, "cond_payload_str") && (i = pl_find(l, "pattern")) >= 0)
        pl_del(l, i);
    if (strcmp(iff, "cond_random") && (i = pl_find(l, "percent")) >= 0)
        pl_del(l, i);
    if (!strcmp(iff, "cond_payload_str") && pl_find(l, "pattern") < 0) {
        sbuf v;
        sb_init(&v);
        gen_pattern_str(&v);
        pl_set(l, "pattern", sb_take(&v));
    }
    (void)g;
}

/* sets key to a drawn value; 0 when it cannot be drawn */
static int draw(const xa_kind *k, const char *key, const strat_xgen *g, plist *l)
{
    sbuf v;
    int r;
    sb_init(&v);
    r = gen_value(k->name, key, g, &v);
    if (r < 0) {
        sb_free(&v);
        return 0;
    }
    if (r == 0) {
        sb_free(&v);
        pl_set(l, key, NULL);
    } else {
        pl_set(l, key, sb_take(&v));
    }
    cond_couple(k, key, g, l);
    return 1;
}

static int add_one(const xa_kind *k, const gkind *gk, const strat_xgen *g, plist *l)
{
    const char *keys[64], *free_keys[64];
    int n = drawable_keys(k, gk, keys, 64), nf = 0;
    for (int i = 0; i < n; i++)
        if (pl_find(l, keys[i]) < 0)
            free_keys[nf++] = keys[i];
    for (int tries = 0; tries < 8 && nf; tries++)
        if (draw(k, free_keys[rng_index((size_t)nf)], g, l))
            return 1;
    return 0;
}

static void add_required(const xa_kind *k, const gkind *gk, const strat_xgen *g, plist *l)
{
    const char *p = gk->req;
    while (p && *p) {
        const char *e = strchr(p, ';');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        char key[32];
        if (n < sizeof(key)) {
            memcpy(key, p, n);
            key[n] = 0;
            if (pl_find(l, key) < 0)
                draw(k, key, g, l);
        }
        p = e ? e + 1 : NULL;
    }
}

/* parses the list as an action of k; 1 with *x when it passes the checks
 * and takes kids subtrees (-1: any) */
static int build(const xa_kind *k, const plist *l, const strat_xgen *g, int kids, void **x, int *got)
{
    char *text = pl_text(l);
    sbuf err;
    int rc;
    sb_init(&err);
    rc = xa_parse(k->name, text, g->dir, x, got, &err);
    free(text);
    sb_free(&err);
    if (rc != 1)
        return 0;
    if (kids >= 0 && *got != kids) {
        xa_free(*x);
        *x = NULL;
        return 0;
    }
    return 1;
}

/* ---- the operators ------------------------------------------------------------------ */

int xgen_random(const strat_xgen *g, void **x, int *kids)
{
    int total = 0;
    const gkind *gk = NULL;
    const xa_kind *k;
    for (size_t i = 0; i < ARRAY_LEN(gkinds); i++)
        if (fits(&gkinds[i], g) && xa_kind_find(gkinds[i].name))
            total += gkinds[i].w;
    if (!total)
        return 0;
    {
        int r = (int)rng_index((size_t)total);
        for (size_t i = 0; i < ARRAY_LEN(gkinds); i++) {
            if (!fits(&gkinds[i], g) || !xa_kind_find(gkinds[i].name))
                continue;
            if (r < gkinds[i].w) {
                gk = &gkinds[i];
                break;
            }
            r -= gkinds[i].w;
        }
    }
    k = xa_kind_find(gk->name);
    for (int tries = 0; tries < 32; tries++) {
        plist l = {.n = 0};
        int extra = (int)rng_index(3), ok;
        add_required(k, gk, g, &l);
        for (int i = 0; i < extra; i++)
            add_one(k, gk, g, &l);
        ok = build(k, &l, g, -1, x, kids);
        pl_free(&l);
        if (ok)
            return 1;
    }
    return 0;
}

/* whether key means the same to both actions: a combinator's pattern is
 * text, xudplen's and the fakes' a blob; xtlsclone's blob and xtag's payload
 * are names they give */
static int same_meaning(const char *from, const char *to, const char *key)
{
    if (!strcmp(key, "pattern"))
        return is_comb(from) == is_comb(to) && !strcmp(from, "xtag") == !strcmp(to, "xtag");
    if (!strcmp(key, "blob"))
        return !strcmp(from, "xtlsclone") == !strcmp(to, "xtlsclone");
    if (!strcmp(key, "payload") || !strcmp(key, "undetected"))
        return !strcmp(from, "xtag") == !strcmp(to, "xtag");
    return 1;
}

/* another action that takes as many subtrees, keeping what parameters it
 * takes and that mean the same; one that sends the real data loses what
 * breaks a packet */
static const xa_kind *retype(const xa_kind *from, const strat_xgen *g, int kids, plist *l, const gkind **gk)
{
    const gkind *cand[ARRAY_LEN(gkinds)];
    size_t n = 0;
    const xa_kind *k;
    for (size_t i = 0; i < ARRAY_LEN(gkinds); i++) {
        const xa_kind *c = xa_kind_find(gkinds[i].name);
        if (c && c != from && c->kids == kids && fits(&gkinds[i], g))
            cand[n++] = &gkinds[i];
    }
    if (!n)
        return NULL;
    *gk = cand[rng_index(n)];
    k = xa_kind_find((*gk)->name);
    for (int i = l->n - 1; i >= 0; i--)
        if (!xa_canon_key(k, l->p[i].k) || (!(*gk)->fool && breaking(l->p[i].k)) ||
            !same_meaning(from->name, k->name, l->p[i].k))
            pl_del(l, i);
    add_required(k, *gk, g, l);
    cond_couple(k, "iff", g, l);
    return k;
}

int xgen_mutate(const strat_xgen *g, void **x, int kids)
{
    const xact *a = *x;
    const gkind *gk = gkind_of(a->kind->name);
    char *old;
    plist start = {.n = 0};
    if (!gk || a->np > GP_MAX)
        return 0; /* the obfuscators, logs, captures, clones: left as written;
                   * so is one with more parameters than a list holds */
    for (int i = 0; i < a->np; i++)
        pl_set(&start, a->p[i].k, a->p[i].v ? xstrdup(a->p[i].v) : NULL);
    old = pl_text(&start);
    for (int tries = 0; tries < 32; tries++) {
        plist l = {.n = 0};
        const xa_kind *k = a->kind;
        const gkind *nk = gk;
        double r = rng_real();
        void *nx = NULL;
        int got, ok = 0;
        char *text;
        for (int i = 0; i < start.n; i++)
            pl_set(&l, start.p[i].k, start.p[i].v ? xstrdup(start.p[i].v) : NULL);
        if (r < 0.15) {
            k = retype(a->kind, g, kids, &l, &nk);
            if (!k)
                k = a->kind;
        } else if (r < 0.60 && l.n) {
            /* a new value for a parameter that has one (a flag stays a
             * flag: it can only go) */
            int i = (int)rng_index((size_t)l.n);
            if (l.p[i].v) {
                char *key = xstrdup(l.p[i].k);
                draw(k, key, g, &l);
                free(key);
            } else {
                add_one(k, nk, g, &l);
            }
        } else if (r < 0.85 || !l.n) {
            add_one(k, nk, g, &l);
        } else {
            pl_del(&l, (int)rng_index((size_t)l.n));
        }
        text = pl_text(&l);
        if (k != a->kind || !text != !old || (text && strcmp(text, old)))
            ok = build(k, &l, g, kids, &nx, &got);
        free(text);
        pl_free(&l);
        if (ok) {
            xa_free(*x);
            *x = nx;
            free(old);
            pl_free(&start);
            return 1;
        }
    }
    free(old);
    pl_free(&start);
    return 0;
}
