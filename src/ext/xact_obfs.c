/*
 * The two-sided obfuscation of zapret2's lua/zapret-obfs.lua (docs/
 * EXT_ROADMAP.md, L1-L4): the same action runs on both ends, in the
 * outbound forest of one and the inbound forest of the other.
 *
 *   xwgobfs{secret=S;padmin=0;padmax=16}  WireGuard's handshake messages
 *       encrypted (AES-128-GCM, key HKDF-SHA256(salt "wgobfs_salt", S),
 *       16 bytes) with random padding: iv(12) tag(16) E(len(2) msg pad)
 *   xippxor{ippxor=N;dataxor=BLOB;rebuild}  the IP protocol number XOR N,
 *       the TCP/UDP/ICMP payload XOR the blob
 *   xudp2icmp{ctype;ccode;stype;scode;dataxor;server;cgnat;id_lifetime}
 *       a UDP datagram as an ICMP message of the same size (echo request
 *       from the client, reply from the server); the ICMP data word keeps
 *       the ports (cgnat: the client also appends them, 2 bytes, as a NAT
 *       may change the identifier, and the server answers with the
 *       identifier it saw)
 *   xsynhide{ghost;ghost6;synack;magic=x2|urp|opt|tsecr;x2;kind;opt;xorseq}
 *       the client's SYN goes as an ACK with a mark (and the server's
 *       SYN,ACK as RST,ACK with synack), turned back on the other end
 *
 * zapret2 changes the dissected packet and reconstructs it; here a change
 * of the protocol builds the packet's bytes and parses them again, with
 * the lengths and the checksums of the new protocol computed.
 */
#include <stdlib.h>
#include <string.h>

#include "ext/l7.h"
#include "ext/xact.h"
#include "plat.h"
#include "rng.h"

#if GENEVA_EXT_CRYPTO
#  include "ext/crypto.h"
#endif

enum { IPP_ICMP = 1, IPP_TCP = 6, IPP_UDP = 17, IPP_ICMP6 = 58 };

static void put16(uint8_t *p, unsigned v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static unsigned get16(const uint8_t *p) { return (unsigned)p[0] << 8 | p[1]; }

/* ---- bytes ------------------------------------------------------------------------- */

/* the L3 header's length and where the final protocol number is (IPv6:
 * the next header that names it, after the extension headers); 0 when the
 * packet is not one we can take apart */
static size_t l3_of(const uint8_t *b, size_t n, size_t *protoff)
{
    size_t off, at;
    if (n < 20)
        return 0;
    if ((b[0] >> 4) == 4) {
        off = (size_t)(b[0] & 15) * 4;
        *protoff = 9;
        return off >= 20 && off <= n ? off : 0;
    }
    if ((b[0] >> 4) != 6 || n < 40)
        return 0;
    at = 6;
    off = 40;
    for (;;) {
        uint8_t nh = b[at];
        size_t l;
        if (nh == 0 || nh == 43 || nh == 60) {
            if (off + 2 > n)
                return 0;
            l = ((size_t)b[off + 1] + 1) * 8;
        } else if (nh == 44) {
            l = 8;
        } else if (nh == 51) {
            if (off + 2 > n)
                return 0;
            l = ((size_t)b[off + 1] + 2) * 4;
        } else {
            break;
        }
        if (off + l > n)
            return 0;
        at = off;
        off += l;
    }
    *protoff = at;
    return off;
}

/* the checksum of the L4 bytes b[l3..n) as protocol proto */
static void l4_csum(uint8_t *b, size_t n, size_t l3, uint8_t proto)
{
    size_t l4 = n - l3, at;
    uint32_t s = 0;
    int v6 = (b[0] >> 4) == 6;
    if (proto == IPP_TCP)
        at = 16;
    else if (proto == IPP_UDP)
        at = 6;
    else if (proto == IPP_ICMP || proto == IPP_ICMP6)
        at = 2;
    else
        return;
    if (at + 2 > l4)
        return;
    put16(b + l3 + at, 0);
    if (proto != IPP_ICMP) {
        const uint8_t *a = v6 ? b + 8 : b + 12;
        for (int i = 0; i < (v6 ? 32 : 8); i += 2)
            s += get16(a + i);
        s += proto + (uint32_t)(l4 >> 16) + (uint32_t)(l4 & 0xffff);
    }
    {
        uint16_t c = inet_csum(b + l3, l4, s);
        if (proto == IPP_UDP && !c)
            c = 0xffff;
        put16(b + l3 + at, c);
    }
}

/* b (n) parsed in place of p, keeping what the engine set on p; -1 when it
 * does not parse */
static int reparse(gpkt *p, const uint8_t *b, size_t n)
{
    gpkt *q = pkt_parse(b, n), keep;
    if (!q)
        return -1;
    keep = *p;
    free(p->payload);
    free(p->raw);
    free(p->ext);
    free(p->opts_tail);
    *p = *q;
    free(q);
    p->sleep = keep.sleep;
    p->xgen = keep.xgen;
    p->xdrop = keep.xdrop;
    p->xmark = keep.xmark;
    memcpy(p->xifout, keep.xifout, sizeof(p->xifout));
    return 0;
}

/* the packet with L4 protocol proto and L4 bytes l4 (n4), lengths and
 * checksums computed, parsed again in place of p; -1 when it cannot be */
static int rebuild(gpkt *p, uint8_t proto, const uint8_t *l4, size_t n4)
{
    uint8_t *b, *nb;
    size_t n, l3, protoff = 0;
    int rc;
    b = pkt_bytes(p, &n);
    if (!b)
        return -1;
    l3 = l3_of(b, n, &protoff);
    if (!l3 || l3 + n4 > PKT_MAX) {
        free(b);
        return -1;
    }
    nb = xmalloc(l3 + n4);
    memcpy(nb, b, l3);
    if (n4)
        memcpy(nb + l3, l4, n4);
    free(b);
    nb[protoff] = proto;
    if ((nb[0] >> 4) == 4) {
        put16(nb + 2, (unsigned)(l3 + n4));
        put16(nb + 10, 0);
        put16(nb + 10, inet_csum(nb, l3, 0));
    } else {
        put16(nb + 4, (unsigned)(l3 + n4 - 40));
    }
    if (proto == IPP_UDP && n4 >= 8)
        put16(nb + l3 + 4, (unsigned)n4);
    l4_csum(nb, l3 + n4, l3, proto);
    rc = reparse(p, nb, l3 + n4);
    free(nb);
    return rc;
}

/* the L4 bytes of p as they go out */
static uint8_t *l4_bytes(gpkt *p, size_t *n4, size_t *l3out)
{
    size_t n, l3, protoff;
    uint8_t *b = pkt_bytes(p, &n), *r;
    if (!b)
        return NULL;
    l3 = l3_of(b, n, &protoff);
    if (!l3) {
        free(b);
        return NULL;
    }
    *n4 = n - l3;
    r = xmalloc(*n4 ? *n4 : 1);
    memcpy(r, b + l3, *n4);
    free(b);
    if (l3out)
        *l3out = l3;
    return r;
}

static int is_icmp(const gpkt *p)
{
    return p->l4 == LAYER_NONE && ((p->ipver == 4 && p->l4proto == IPP_ICMP) || (p->ipver == 6 && p->l4proto == IPP_ICMP6));
}

static void xor_pattern(xrun *r, const uint8_t *pat, size_t pl, uint8_t *d, size_t n)
{
    uint8_t *m;
    (void)r;
    if (!n)
        return;
    m = xmalloc(n);
    xa_pattern(pat, pl, 1, m, n);
    for (size_t i = 0; i < n; i++)
        d[i] ^= m[i];
    free(m);
}

/* ---- wgobfs ------------------------------------------------------------------------- */

#if GENEVA_EXT_CRYPTO
typedef struct {
    uint8_t key[16];
} wg_priv;

static void wg_key(const uint8_t *secret, size_t n, uint8_t key[16])
{
    static const char salt[] = "wgobfs_salt";
    uint8_t prk[32];
    hkdf_extract((const uint8_t *)salt, sizeof(salt) - 1, secret, n, prk);
    hkdf_expand(prk, NULL, 0, key, 16);
    secure_zero(prk, sizeof(prk));
}
#endif

static int check_wgobfs(const xact *a, sbuf *err)
{
#if !GENEVA_EXT_CRYPTO
    (void)a;
    sb_puts(err, "xwgobfs: this build has no cryptography (EXT_CRYPTO=0)");
    return -1;
#else
    const char *s = xa_raw(a, "secret"), *mn = xa_raw(a, "padmin"), *mx = xa_raw(a, "padmax");
    int64_t a1 = 0, a2 = 16;
    if (!s || !*s) {
        sb_puts(err, "xwgobfs: secret required");
        return -1;
    }
    if (xa_check_num(a, "padmin", 0, 65535, err) < 0 || xa_check_num(a, "padmax", 0, 65535, err) < 0)
        return -1;
    if ((!mn || (mn[0] != '#' && mn[0] != '%')) && (!mx || (mx[0] != '#' && mx[0] != '%'))) {
        if (mn)
            xa_parse_int(mn, &a1);
        if (mx)
            xa_parse_int(mx, &a2);
        if (a1 > a2) {
            sb_puts(err, "xwgobfs: padmin>padmax");
            return -1;
        }
    }
    return 0;
#endif
}

#if GENEVA_EXT_CRYPTO
static int prepare_wgobfs(xact *a, sbuf *err)
{
    const char *s = xa_raw(a, "secret");
    wg_priv *w;
    (void)err;
    if (!s || s[0] == '%' || s[0] == '#')
        return 0; /* known on the packet */
    w = xmalloc(sizeof(*w));
    wg_key((const uint8_t *)s, strlen(s), w->key);
    a->priv = w;
    return 0;
}

static void release_wgobfs(xact *a)
{
    if (a->priv)
        secure_zero(a->priv, sizeof(wg_priv));
    free(a->priv);
    a->priv = NULL;
}
#endif

static void run_wgobfs(const xact *a, gpkt *p, xrun *r)
{
#if !GENEVA_EXT_CRYPTO
    (void)a;
    xa_pass(r, p);
#else
    static const size_t sizes[] = {2 + 12 + 16 + 148, 2 + 12 + 16 + 92, 2 + 12 + 16 + 64};
    int64_t padmin, padmax;
    size_t len = p->payload_len, n;
    uint8_t key[16];
    gcm_ctx g;
    if (p->l4 != LAYER_UDP) {
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    if (xa_num(r, "padmin", 0, 0, 65535, &padmin) < 0 || xa_num(r, "padmax", 16, 0, 65535, &padmax) < 0 ||
        padmin > padmax) {
        xa_pass(r, p);
        return;
    }
    if (a->priv) {
        memcpy(key, ((const wg_priv *)a->priv)->key, 16);
    } else {
        const char *s = xa_arg(r, "secret", &n);
        if (!s || !n) {
            xa_log(r, "secret required");
            xa_pass(r, p);
            return;
        }
        wg_key((const uint8_t *)s, n, key);
    }
    gcm_init(&g, key, 16);
    if ((r->l7p == L7P_WIREGUARD_INITIATION || r->l7p == L7P_WIREGUARD_RESPONSE || r->l7p == L7P_WIREGUARD_COOKIE) &&
        len < 65506) {
        size_t pad = (size_t)(padmin + (padmax > padmin ? (int64_t)rng_range(0, (int)(padmax - padmin)) : 0));
        size_t pn = 2 + len + pad;
        uint8_t *plain = xmalloc(pn), *out = xmalloc(28 + pn);
        put16(plain, (unsigned)len);
        if (len)
            memcpy(plain + 2, p->payload, len);
        plat_random_bytes(plain + 2 + len, pad);
        /* every message its own random iv, sent with it: a repeated iv
         * breaks AES-GCM, so without the system's generator nothing is
         * encrypted */
        if (plat_random_secure(out, 12) < 0) {
            xa_log(r, "no secure random numbers: not encrypted");
        } else {
            gcm_encrypt(&g, out, NULL, 0, plain, out + 28, pn, out + 12);
            xa_log(r, "encrypting %zu bytes", len);
            pkt_set_payload(p, out, 28 + pn);
            xa_modified(p);
        }
        free(plain);
        free(out);
    } else if (r->l7p == L7P_UNKNOWN) {
        int fits = 0;
        for (size_t i = 0; i < sizeof(sizes) / sizeof(*sizes); i++)
            if (len >= sizes[i] + (size_t)padmin && len <= sizes[i] + (size_t)padmax)
                fits = 1;
        if (fits) {
            uint8_t *plain = xmalloc(len - 28);
            if (gcm_decrypt(&g, p->payload, NULL, 0, p->payload + 28, plain, len - 28, p->payload + 12) < 0) {
                xa_log(r, "decrypt auth tag mismatch");
            } else {
                size_t plen = get16(plain);
                if (plen > len - 28 - 2) {
                    xa_log(r, "bad decrypted payload data");
                } else {
                    xa_log(r, "decrypted %zu bytes", plen);
                    pkt_set_payload(p, plain + 2, plen);
                    xa_modified(p);
                }
            }
            free(plain);
        }
    }
    secure_zero(key, sizeof(key));
    secure_zero(&g, sizeof(g));
    xa_pass(r, p);
#endif
}

/* ---- ippxor -------------------------------------------------------------------------- */

static int check_ippxor(const xact *a, sbuf *err)
{
    if (!xa_raw(a, "ippxor")) {
        sb_puts(err, "xippxor: ippxor value required");
        return -1;
    }
    if (xa_check_num(a, "ippxor", 0, 255, err) < 0 || xa_check_blob(a, "dataxor", err) < 0 ||
        xa_check_flag(a, "rebuild", err) < 0)
        return -1;
    return 0;
}

/* the payload of a TCP, UDP or ICMP packet: where it starts in the L4 bytes */
static int payload_at(const gpkt *p, const uint8_t *l4, size_t n4, size_t *at)
{
    if (p->l4 == LAYER_TCP) {
        *at = (size_t)(l4[12] >> 4) * 4;
    } else if (p->l4 == LAYER_UDP) {
        *at = 8;
    } else if (is_icmp(p)) {
        *at = 8;
    } else {
        return 0;
    }
    return *at < n4;
}

static void run_ippxor(const xact *a, gpkt *p, xrun *r)
{
    int64_t x;
    size_t dl = 0, n4 = 0, n, l3, protoff, at;
    const uint8_t *dx = NULL;
    const char *dn;
    uint8_t *l4, *b, from, to;
    int bdxor = 0;
    (void)a;
    if (xa_num(r, "ippxor", 0, 0, 255, &x) < 0) {
        xa_pass(r, p);
        return;
    }
    if ((dn = xa_arg(r, "dataxor", NULL)) != NULL && (!(dx = xa_blob(r, dn, &dl, 0)) || !dl)) {
        xa_log(r, "empty dataxor value");
        xa_pass(r, p);
        return;
    }
    if (!(l4 = l4_bytes(p, &n4, NULL))) {
        xa_pass(r, p);
        return;
    }
    if (dx && payload_at(p, l4, n4, &at)) {
        xor_pattern(r, dx, dl, l4 + at, n4 - at);
        bdxor = 1;
    }
    from = p->ipver == 4 ? p->proto : p->l4proto;
    to = (uint8_t)(from ^ (uint8_t)x);
    xa_log(r, "%u => %u", from, to);
    /* the checksum as what the packet is now (TCP, UDP and ICMP keep a
     * right one under the other number, for the other end), then the number
     * alone changes */
    if (rebuild(p, from, l4, n4) < 0 || !(b = pkt_bytes(p, &n))) {
        free(l4);
        xa_pass(r, p);
        return;
    }
    free(l4);
    if ((l3 = l3_of(b, n, &protoff)) != 0) {
        b[protoff] = to;
        if (p->ipver == 4) {
            put16(b + 10, 0);
            put16(b + 10, inet_csum(b, l3, 0));
        }
        /* a packet that becomes TCP, UDP or ICMP is taken apart as one
         * (zapret2's rebuild), and its payload XORed then */
        if (reparse(p, b, n) == 0 && dx && !bdxor && (l4 = l4_bytes(p, &n4, NULL)) != NULL) {
            if (payload_at(p, l4, n4, &at)) {
                xor_pattern(r, dx, dl, l4 + at, n4 - at);
                rebuild(p, to, l4, n4);
            }
            free(l4);
        }
    }
    free(b);
    xa_pass(r, p);
}

/* ---- udp2icmp ------------------------------------------------------------------------ */

static const char *const k_byte[] = {"ctype", "ccode", "stype", "scode"};

static int check_udp2icmp(const xact *a, sbuf *err)
{
    for (int i = 0; i < 4; i++)
        if (xa_check_num(a, k_byte[i], 0, 255, err) < 0)
            return -1;
    if (!xa_has(a, "ctype") != !xa_has(a, "stype")) {
        sb_puts(err, "xudp2icmp: ctype and stype must be both set or not set");
        return -1;
    }
    if (!xa_has(a, "ccode") != !xa_has(a, "scode")) {
        sb_puts(err, "xudp2icmp: ccode and scode must be both set or not set");
        return -1;
    }
    if (xa_check_blob(a, "dataxor", err) < 0 || xa_check_num(a, "server", 0, 1, err) < 0 ||
        xa_check_flag(a, "cgnat", err) < 0 || xa_check_num(a, "id_lifetime", 1, 86400, err) < 0)
        return -1;
    return 0;
}

/* cgnat: the ICMP identifier the server saw, by the client's and the
 * server's address and port (zapret2's udp2icmp_map), shared by the
 * inbound and the outbound action and by the workers */
enum { IDMAP_N = 4096, IDMAP_PROBE = 8 };

typedef struct {
    uint8_t key[36]; /* client address, server address (16 bytes each), client port, server port */
    uint16_t id;
    uint64_t t; /* ms; 0: free */
} idmap_ent;

static idmap_ent idmap[IDMAP_N];
static plat_mutex_t idmap_lock;
static int idmap_ready;

static void idmap_init(void)
{
    if (!idmap_ready) { /* at parse time, before the workers */
        plat_mutex_init(&idmap_lock);
        idmap_ready = 1;
    }
}

static void idmap_key(const gpkt *p, int client_is_src, unsigned cport, unsigned sport, uint8_t key[36])
{
    size_t al = p->ipver == 6 ? 16 : 4;
    memset(key, 0, 36);
    memcpy(key, client_is_src ? p->src : p->dst, al);
    memcpy(key + 16, client_is_src ? p->dst : p->src, al);
    put16(key + 32, cport);
    put16(key + 34, sport);
}

static size_t idmap_slot(const uint8_t key[36])
{
    uint32_t h = 2166136261u;
    for (int i = 0; i < 36; i++)
        h = (h ^ key[i]) * 16777619u;
    return h % IDMAP_N;
}

static void idmap_put(const uint8_t key[36], uint16_t id, uint64_t now)
{
    size_t b = idmap_slot(key), at = b;
    plat_mutex_lock(&idmap_lock);
    for (size_t i = 0; i < IDMAP_PROBE; i++) {
        idmap_ent *e = &idmap[(b + i) % IDMAP_N];
        if (e->t && !memcmp(e->key, key, 36)) {
            at = (b + i) % IDMAP_N;
            break;
        }
        if (e->t < idmap[at].t) /* free, or the oldest */
            at = (b + i) % IDMAP_N;
    }
    memcpy(idmap[at].key, key, 36);
    idmap[at].id = id;
    idmap[at].t = now ? now : 1;
    plat_mutex_unlock(&idmap_lock);
}

/* 0 and *id, or -1 when not there or older than life ms */
static int idmap_get(const uint8_t key[36], uint64_t now, uint64_t life, uint16_t *id)
{
    size_t b = idmap_slot(key);
    int rc = -1;
    plat_mutex_lock(&idmap_lock);
    for (size_t i = 0; i < IDMAP_PROBE; i++) {
        idmap_ent *e = &idmap[(b + i) % IDMAP_N];
        if (e->t && !memcmp(e->key, key, 36)) {
            if (now >= e->t + life) {
                e->t = 0;
            } else {
                *id = e->id;
                e->t = now ? now : 1; /* used: lives on */
                rc = 0;
            }
            break;
        }
    }
    plat_mutex_unlock(&idmap_lock);
    return rc;
}

static int prepare_udp2icmp(xact *a, sbuf *err)
{
    (void)err;
    if (xa_has(a, "cgnat"))
        idmap_init();
    return 0;
}

static void run_udp2icmp(const xact *a, gpkt *p, xrun *r)
{
    int64_t v[4], server, life;
    int cgnat = xa_has(a, "cgnat") && idmap_ready;
    uint8_t key[36];
    int v6 = p->ipver == 6;
    size_t dl = 0, n4 = 0;
    const uint8_t *dx = NULL;
    const char *dn;
    unsigned tsend, csend, trecv, crecv;
    for (int i = 0; i < 4; i++)
        if (xa_num(r, k_byte[i], -1, 0, 255, &v[i]) < 0) {
            xa_pass(r, p);
            return;
        }
    if (xa_num(r, "server", 0, 0, 1, &server) < 0 || xa_num(r, "id_lifetime", 60, 1, 86400, &life) < 0) {
        xa_pass(r, p);
        return;
    }
    if (v[0] < 0) {
        v[0] = v6 ? 128 : 8; /* echo request */
        v[2] = v6 ? 129 : 0; /* echo reply */
    }
    if (v[1] < 0)
        v[1] = v[3] = 0;
    /* the client sends ctype and gets stype, the server the other way */
    tsend = (unsigned)(server ? v[2] : v[0]);
    csend = (unsigned)(server ? v[3] : v[1]);
    trecv = (unsigned)(server ? v[0] : v[2]);
    crecv = (unsigned)(server ? v[1] : v[3]);
    if ((dn = xa_arg(r, "dataxor", NULL)) != NULL && (!(dx = xa_blob(r, dn, &dl, 0)) || !dl)) {
        xa_log(r, "empty dataxor value");
        xa_pass(r, p);
        return;
    }
    if (p->l4 == LAYER_UDP) {
        unsigned id = p->sport ^ p->dport;
        uint8_t *m = xmalloc(8 + p->payload_len + 2);
        uint16_t mid;
        n4 = 8 + p->payload_len;
        m[0] = (uint8_t)tsend;
        m[1] = (uint8_t)csend;
        put16(m + 2, 0);
        if (p->payload_len)
            memcpy(m + 8, p->payload, p->payload_len);
        if (dx)
            xor_pattern(r, dx, dl, m + 8, p->payload_len);
        if (cgnat && server) {
            /* the identifier as it came, or the NAT does not deliver */
            idmap_key(p, 0, p->dport, p->sport, key);
            if (idmap_get(key, plat_now_ms(), (uint64_t)life * 1000, &mid) == 0) {
                id = mid;
                xa_log(r, "found mapped icmp identifier %04X", id);
            } else {
                xa_log(r, "mapped icmp identifier NOT found !");
            }
        } else if (cgnat) {
            /* after the XOR, as zapret2 appends it to the XORed payload */
            put16(m + n4, id);
            n4 += 2;
            xa_log(r, "expanding udp size to %zu", n4 - 8);
        }
        /* the data word: the identifier (sport^dport), then the port of the
         * other end */
        put16(m + 4, id);
        put16(m + 6, server ? p->sport : p->dport);
        xa_log(r, "udp => icmp sport=%u dport=%u size=%zu", p->sport, p->dport, p->payload_len);
        rebuild(p, v6 ? IPP_ICMP6 : IPP_ICMP, m, n4);
        free(m);
    } else if (is_icmp(p) && p->payload_len >= 8 && p->payload[0] == trecv && p->payload[1] == crecv) {
        unsigned id = get16(p->payload + 4), pl = get16(p->payload + 6), pm = id ^ pl;
        size_t dlen = p->payload_len - 8;
        uint8_t *m;
        if (cgnat && server) {
            if (dlen < 2) {
                xa_log(r, "udp is less than 2 bytes and cgnat is on ! doing nothing");
                xa_pass(r, p);
                return;
            }
            pm = get16(p->payload + p->payload_len - 2) ^ pl;
            dlen -= 2;
            idmap_key(p, 1, pm, pl, key);
            idmap_put(key, (uint16_t)id, plat_now_ms());
            xa_log(r, "shrinking udp size to %zu, stored mapped icmp identifier %04X", dlen, id);
        }
        m = xmalloc(8 + dlen);
        put16(m, server ? pm : pl);
        put16(m + 2, server ? pl : pm);
        put16(m + 4, (unsigned)(8 + dlen));
        put16(m + 6, 0);
        if (dlen)
            memcpy(m + 8, p->payload + 8, dlen);
        if (dx)
            xor_pattern(r, dx, dl, m + 8, dlen);
        xa_log(r, "icmp => udp sport=%u dport=%u size=%zu", get16(m), get16(m + 2), dlen);
        rebuild(p, IPP_UDP, m, 8 + dlen);
        free(m);
    }
    xa_pass(r, p);
}

/* ---- synhide -------------------------------------------------------------------------- */

enum { MG_X2, MG_URP, MG_OPT, MG_TSECR };
enum { TH_FIN = 1, TH_SYN = 2, TH_RST = 4, TH_ACK = 16, TH_URG = 32 };

static int check_synhide(const xact *a, sbuf *err)
{
    const char *m = xa_raw(a, "magic"), *o = xa_raw(a, "opt"), *x = xa_raw(a, "xorseq");
    uint8_t buf[64];
    if (m && strcmp(m, "x2") && strcmp(m, "urp") && strcmp(m, "opt") && strcmp(m, "tsecr")) {
        sb_printf(err, "xsynhide: invalid magic mode '%s'", m);
        return -1;
    }
    if (xa_check_num(a, "x2", 1, 15, err) < 0 || xa_check_num(a, "kind", 2, 255, err) < 0 ||
        xa_check_num(a, "ghost", 1, 255, err) < 0 || xa_check_num(a, "ghost6", 1, 255, err) < 0 ||
        xa_check_flag(a, "synack", err) < 0)
        return -1;
    if (o && o[0] != '%' && (hex_decode(o, buf, 38) < 0)) {
        sb_puts(err, "xsynhide: invalid opt value");
        return -1;
    }
    if (x && x[0] != '%' && hex_decode(x, buf, sizeof(buf)) != 4) {
        sb_puts(err, "xsynhide: invalid xorseq value");
        return -1;
    }
    return 0;
}

static int find_opt(const gpkt *p, uint8_t kind)
{
    for (int i = 0; i < p->nopts; i++)
        if (p->opts[i].kind == kind)
            return i;
    return -1;
}

typedef struct {
    int magic, x2, kind, has_xor;
    uint8_t opt[38];
    size_t optl;
    uint32_t xorseq;
    int ts;
} sh_cfg;

static unsigned make_magic(const gpkt *p, int client)
{
    uint32_t m = client ? p->seq : p->ack - 1;
    unsigned v = (m >> 16) ^ (m & 0xffff);
    return v ? v : (client ? p->dport : p->sport); /* 0 is not acceptable */
}

static void xorhdr(gpkt *p, const sh_cfg *c)
{
    if (c->has_xor) {
        p->ack ^= c->xorseq;
        p->seq ^= c->xorseq;
    }
}

/* th_x2 is the 4 bits before the flags: geneva keeps its low bit as NS */
static unsigned get_x2(const gpkt *p) { return (unsigned)(p->reserved << 1) | ((p->tcpflags >> 8) & 1); }

static void set_x2(gpkt *p, unsigned v)
{
    p->reserved = (uint8_t)((v >> 1) & 7);
    p->tcpflags = (uint16_t)((p->tcpflags & 0xff) | ((v & 1) << 8));
}

static int ver_magic(gpkt *p, const sh_cfg *c, int client)
{
    int r = 0, i;
    xorhdr(p, c);
    if (c->magic == MG_TSECR) {
        r = c->ts >= 0 && p->opts[c->ts].len >= 8 && get16(p->opts[c->ts].data + 6) == make_magic(p, client);
    } else if (c->magic == MG_X2) {
        r = (get_x2(p) & (unsigned)c->x2) != 0;
    } else if (c->magic == MG_URP) {
        r = p->urgptr == make_magic(p, client);
    } else if ((i = find_opt(p, (uint8_t)c->kind)) >= 0) {
        r = p->opts[i].len == c->optl && !memcmp(p->opts[i].data, c->opt, c->optl);
    }
    xorhdr(p, c);
    return r;
}

static int set_magic(gpkt *p, const sh_cfg *c, int client)
{
    if (c->magic == MG_TSECR) {
        put16(p->opts[c->ts].data + 6, make_magic(p, client));
    } else if (c->magic == MG_X2) {
        set_x2(p, get_x2(p) | (unsigned)c->x2);
    } else if (c->magic == MG_URP) {
        p->urgptr = (uint16_t)make_magic(p, client);
    } else {
        size_t used = p->opts_tail_len;
        for (int i = 0; i < p->nopts; i++)
            used += p->opts[i].kind <= 1 ? 1 : (size_t)p->opts[i].len + 2;
        /* the builder drops what does not fit in 40 bytes: the mark would
         * be lost and the SYN with it */
        if (p->nopts >= TCP_MAX_OPTS || used + 2 + c->optl > 40)
            return -1;
        p->opts[p->nopts].kind = (uint8_t)c->kind;
        p->opts[p->nopts].len = (uint8_t)c->optl;
        memcpy(p->opts[p->nopts].data, c->opt, c->optl);
        p->nopts++;
    }
    xorhdr(p, c);
    return 0;
}

static void clear_magic(gpkt *p, const sh_cfg *c)
{
    int i;
    xorhdr(p, c);
    if (c->magic == MG_TSECR) {
        put16(p->opts[c->ts].data + 6, 0);
    } else if (c->magic == MG_X2) {
        set_x2(p, get_x2(p) & ~(unsigned)c->x2);
    } else if (c->magic == MG_URP) {
        p->urgptr = 0;
    } else if ((i = find_opt(p, (uint8_t)c->kind)) >= 0) {
        memmove(&p->opts[i], &p->opts[i + 1], (size_t)(p->nopts - i - 1) * sizeof(p->opts[0]));
        p->nopts--;
    }
}

static void run_synhide(const xact *a, gpkt *p, xrun *r)
{
    sh_cfg c;
    const char *m, *v;
    int64_t n, ghost;
    unsigned fl;
    int synack = xa_has(a, "synack");
    if (p->l4 != LAYER_TCP) {
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    memset(&c, 0, sizeof(c));
    fl = p->tcpflags & (TH_SYN | TH_ACK | TH_FIN | TH_RST | TH_URG);
    c.ts = find_opt(p, 8);
    m = xa_arg(r, "magic", NULL);
    c.magic = !m || !strcmp(m, "x2") ? MG_X2 : !strcmp(m, "urp") ? MG_URP : !strcmp(m, "opt") ? MG_OPT : MG_TSECR;
    if (c.magic == MG_TSECR && c.ts < 0) {
        xa_log(r, "cannot use tsecr magic because timestamp option is absent");
        xa_cutoff(r);
        xa_pass(r, p);
        return;
    }
    if (xa_num(r, "x2", 1, 1, 15, &n) < 0) {
        xa_pass(r, p);
        return;
    }
    c.x2 = (int)n;
    if (xa_num(r, "kind", 172, 2, 255, &n) < 0) { /* 172: accurate ECN */
        xa_pass(r, p);
        return;
    }
    c.kind = (int)n;
    if ((v = xa_arg(r, "opt", NULL)) != NULL) {
        long k = hex_decode(v, c.opt, sizeof(c.opt));
        if (k < 0) {
            xa_log(r, "invalid opt value");
            xa_pass(r, p);
            return;
        }
        c.optl = (size_t)k;
    }
    if ((v = xa_arg(r, "xorseq", NULL)) != NULL) {
        uint8_t x[8];
        if (hex_decode(v, x, sizeof(x)) != 4) {
            xa_log(r, "invalid xorseq value");
            xa_pass(r, p);
            return;
        }
        c.has_xor = 1;
        c.xorseq = (uint32_t)x[0] << 24 | (uint32_t)x[1] << 16 | (uint32_t)x[2] << 8 | x[3];
    }

    if (fl == TH_SYN) {
        /* the client's SYN */
        if (xa_num(r, p->ipver == 4 ? "ghost" : "ghost6", 0, 0, 255, &ghost) < 0) {
            xa_pass(r, p);
            return;
        }
        if (ghost) {
            gpkt *g = pkt_copy(p);
            xsendopt o;
            memset(&o, 0, sizeof(o));
            o.repeats = 1;
            o.ipid = -1;
            if (g->ipver == 4)
                g->ttl = (uint8_t)ghost;
            else
                g->hlim = (uint8_t)ghost;
            xa_log(r, "punch NAT hole with ttl=%d", (int)ghost);
            if (xa_send_ipfrag(r, g, &o) < 0) {
                pkt_free(g);
                xa_cutoff(r);
                xa_pass(r, p);
                return;
            }
            pkt_free(g);
        }
        if (set_magic(p, &c, 1) < 0) {
            xa_log(r, "no room for the option");
            xa_cutoff(r);
            xa_pass(r, p);
            return;
        }
        p->tcpflags = (uint16_t)((p->tcpflags & ~TH_SYN) | TH_ACK);
        xa_log(r, "client sends SYN. remove SYN");
        if (!synack)
            xa_cutoff(r);
        xa_modified(p);
    } else if (fl == (TH_SYN | TH_ACK)) {
        if (synack) {
            set_magic(p, &c, 0);
            p->tcpflags = (uint16_t)((p->tcpflags & ~TH_SYN) | TH_RST);
            xa_log(r, "server sends SYN+ACK. remove SYN, set RST");
            xa_modified(p);
        } else {
            xa_cutoff(r);
        }
    } else if (fl == TH_ACK && ver_magic(p, &c, 1)) {
        p->tcpflags = (uint16_t)((p->tcpflags & ~TH_ACK) | TH_SYN);
        clear_magic(p, &c);
        xa_log(r, "server received magic. restore SYN");
        if (!synack)
            xa_cutoff(r);
        xa_modified(p);
    } else if (fl == (TH_ACK | TH_RST) && ver_magic(p, &c, 0)) {
        p->tcpflags = (uint16_t)((p->tcpflags & ~TH_RST) | TH_SYN);
        clear_magic(p, &c);
        xa_log(r, "client received magic. restore SYN, remove RST");
        xa_cutoff(r);
        xa_modified(p);
    } else {
        xa_log(r, "sequence failed");
        xa_cutoff(r);
    }
    xa_pass(r, p);
}

static const char *const k_wgobfs[] = {"secret", "padmin", "padmax", NULL};
static const char *const k_ippxor[] = {"ippxor", "dataxor", "rebuild", NULL};
static const char *const k_udp2icmp[] = {"ctype", "ccode", "stype", "scode", "dataxor", "server", "cgnat", "id_lifetime", NULL};
static const char *const k_synhide[] = {"ghost", "ghost6", "synack", "magic", "x2", "kind", "opt", "xorseq", NULL};

#if GENEVA_EXT_CRYPTO
const xa_kind xa_wgobfs = {"xwgobfs", 1, 1, 0, k_wgobfs, check_wgobfs, run_wgobfs, prepare_wgobfs, release_wgobfs};
#else
const xa_kind xa_wgobfs = {"xwgobfs", 1, 1, 0, k_wgobfs, check_wgobfs, run_wgobfs, NULL, NULL};
#endif
const xa_kind xa_ippxor = {"xippxor", 1, 1, 0, k_ippxor, check_ippxor, run_ippxor, NULL, NULL};
const xa_kind xa_udp2icmp = {"xudp2icmp", 1, 1, 0, k_udp2icmp, check_udp2icmp, run_udp2icmp, prepare_udp2icmp, NULL};
const xa_kind xa_synhide = {"xsynhide", 1, 1, 0, k_synhide, check_synhide, run_synhide, NULL, NULL};
