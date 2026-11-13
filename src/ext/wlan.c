#include "wlan.h"

#include <string.h>

#include "log.h"
#include "plat.h"

/* ---- messages (every platform: the tests) ---------------------------------- */

#define A4(n) (((n) + 3u) & ~3u)
#define NLH 16
#define GENLH 4
#define NLA_TYPE_MASK 0x3fff
#define NLMSG_ERROR_ 2
#define NLMSG_DONE_ 3
#define GENL_ID_CTRL_ 0x10
#define CTRL_CMD_GETFAMILY_ 3
#define CTRL_ATTR_FAMILY_ID_ 1
#define CTRL_ATTR_FAMILY_NAME_ 2

/* nl80211.h */
enum { CMD_GET_INTERFACE = 5, CMD_GET_SCAN = 32 };
enum { ATTR_IFINDEX = 3, ATTR_IFNAME = 4, ATTR_BSS = 47, ATTR_SSID = 52 };
enum { BSS_INFORMATION_ELEMENTS = 6, BSS_STATUS = 9 };
enum { BSS_STATUS_AUTHENTICATED = 0, BSS_STATUS_ASSOCIATED = 1, BSS_STATUS_IBSS_JOINED = 2 };

/* netlink's fields in host order */
static void h16put(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static void h32put(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static uint16_t h16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}
static uint32_t h32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

size_t xwlan_build(uint8_t *b, size_t cap, uint16_t family, uint16_t flags, uint32_t seq, uint8_t cmd, uint16_t attr,
                   const void *data, size_t len)
{
    size_t n = NLH + GENLH;
    if (cap < n + 4 + A4(len))
        return 0;
    memset(b, 0, n);
    h16put(b + 4, family);
    h16put(b + 6, flags);
    h32put(b + 8, seq);
    b[NLH] = cmd;
    b[NLH + 1] = 1; /* version */
    if (attr) {
        h16put(b + n, (uint16_t)(4 + len));
        h16put(b + n + 2, attr);
        memcpy(b + n + 4, data, len);
        memset(b + n + 4 + len, 0, A4(len) - len);
        n += 4 + A4(len);
    }
    h32put(b, (uint32_t)n);
    return n;
}

typedef void (*attr_fn)(uint16_t type, const uint8_t *d, size_t n, void *ud);

static void attrs(const uint8_t *p, size_t n, attr_fn fn, void *ud)
{
    while (n >= 4) {
        size_t l = h16(p);
        if (l < 4 || l > n)
            return;
        fn(h16(p + 2) & NLA_TYPE_MASK, p + 4, l - 4, ud);
        if (A4(l) >= n)
            return;
        p += A4(l);
        n -= A4(l);
    }
}

/* walks the messages of one datagram: fn gets the generic netlink payload
 * (attributes) of each answer to seq; 1 at the end, 0 for more, -1 */
typedef int (*msg_fn)(const uint8_t *a, size_t n, void *ud);

static int messages(const uint8_t *b, size_t n, uint32_t seq, msg_fn fn, void *ud, int *err)
{
    *err = 0;
    while (n >= NLH) {
        size_t l = h32(b);
        uint16_t type = h16(b + 4);
        if (l < NLH || l > n)
            return -1;
        if (h32(b + 8) == seq) {
            if (type == NLMSG_DONE_)
                return 1;
            if (type == NLMSG_ERROR_) {
                int32_t e;
                if (l < NLH + 4)
                    return -1;
                memcpy(&e, b + NLH, 4);
                if (!e)
                    return 1; /* an acknowledgement */
                *err = -e;
                return -1;
            }
            if (l >= NLH + GENLH) {
                int r = fn(b + NLH + GENLH, l - NLH - GENLH, ud);
                if (r)
                    return r;
            }
        }
        if (A4(l) >= n)
            break;
        b += A4(l);
        n -= A4(l);
    }
    return 0;
}

static void on_family(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    if (type == CTRL_ATTR_FAMILY_ID_ && n >= 2)
        *(uint16_t *)ud = h16(d);
}

static int family_msg(const uint8_t *a, size_t n, void *ud)
{
    uint16_t id = 0;
    attrs(a, n, on_family, &id);
    if (!id)
        return -1;
    *(uint16_t *)ud = id;
    return 1;
}

int xwlan_parse_family(const uint8_t *buf, size_t n, uint32_t seq, uint16_t *id, int *err)
{
    return messages(buf, n, seq, family_msg, id, err);
}

static void on_iface(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    xwlan_if *w = ud;
    if (type == ATTR_IFINDEX && n >= 4)
        w->ifindex = h32(d);
    else if (type == ATTR_IFNAME && n) {
        size_t l = strnlen((const char *)d, n);
        if (l >= sizeof(w->ifname))
            l = sizeof(w->ifname) - 1;
        memcpy(w->ifname, d, l);
        w->ifname[l] = 0;
    } else if (type == ATTR_SSID) {
        size_t l = n < sizeof(w->ssid) - 1 ? n : sizeof(w->ssid) - 1;
        memcpy(w->ssid, d, l);
        w->ssid[l] = 0;
    }
}

static int iface_msg(const uint8_t *a, size_t n, void *ud)
{
    xwlan_set *s = ud;
    xwlan_if w;
    memset(&w, 0, sizeof(w));
    attrs(a, n, on_iface, &w);
    if (!w.ifindex || !w.ifname[0] || s->n >= XWLAN_MAX)
        return 0;
    for (int i = 0; i < s->n; i++)
        if (s->v[i].ifindex == w.ifindex)
            return 0; /* one entry per interface */
    s->v[s->n++] = w;
    return 0;
}

int xwlan_parse_ifaces(const uint8_t *buf, size_t n, uint32_t seq, xwlan_set *s, int *err)
{
    return messages(buf, n, seq, iface_msg, s, err);
}

/* the SSID element (id 0) of the information elements */
static int ie_ssid(const uint8_t *p, size_t n, char *out)
{
    while (n >= 2) {
        size_t l = p[1];
        if (n < 2 + l)
            return 0;
        if (p[0] == 0) {
            if (l > 32)
                l = 32;
            memcpy(out, p + 2, l);
            out[l] = 0;
            return 1;
        }
        p += 2 + l;
        n -= 2 + l;
    }
    return 0;
}

typedef struct {
    int status_ok;
    int has_ssid;
    char ssid[33];
} bss_info;

static void on_bss(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    bss_info *b = ud;
    if (type == BSS_STATUS && n >= 4) {
        uint32_t st = h32(d);
        b->status_ok = st == BSS_STATUS_ASSOCIATED || st == BSS_STATUS_AUTHENTICATED || st == BSS_STATUS_IBSS_JOINED;
    } else if (type == BSS_INFORMATION_ELEMENTS) {
        b->has_ssid = ie_ssid(d, n, b->ssid);
    }
}

typedef struct {
    uint32_t ifindex;
    bss_info bss;
} scan_info;

static void on_scan(uint16_t type, const uint8_t *d, size_t n, void *ud)
{
    scan_info *si = ud;
    if (type == ATTR_IFINDEX && n >= 4)
        si->ifindex = h32(d);
    else if (type == ATTR_BSS) {
        bss_info b;
        memset(&b, 0, sizeof(b));
        attrs(d, n, on_bss, &b);
        if (b.status_ok && b.has_ssid)
            si->bss = b;
    }
}

static int scan_msg(const uint8_t *a, size_t n, void *ud)
{
    xwlan_set *s = ud;
    scan_info si;
    memset(&si, 0, sizeof(si));
    attrs(a, n, on_scan, &si);
    if (!si.ifindex || !si.bss.has_ssid)
        return 0;
    for (int i = 0; i < s->n; i++)
        if (s->v[i].ifindex == si.ifindex)
            memcpy(s->v[i].ssid, si.bss.ssid, sizeof(si.bss.ssid));
    return 0;
}

int xwlan_parse_scan(const uint8_t *buf, size_t n, uint32_t seq, xwlan_set *s, int *err)
{
    return messages(buf, n, seq, scan_msg, s, err);
}

/* ---- the table ----------------------------------------------------------------- */

static struct {
    int on;
    int fd;
    uint16_t family;
    uint32_t seq;
    plat_mutex_t lock;
    xwlan_set set;
    uint64_t last_sec;
    int busy;
} g = {.fd = -1};

int xwlan_on(void) { return g.on; }

int xwlan_ssid(const char *ifname, char *out)
{
    int r = 0;
    if (!g.on || !ifname)
        return 0;
    plat_mutex_lock(&g.lock);
    for (int i = 0; i < g.set.n; i++)
        if (!strcmp(g.set.v[i].ifname, ifname) && g.set.v[i].ssid[0]) {
            memcpy(out, g.set.v[i].ssid, sizeof(g.set.v[i].ssid));
            r = 1;
            break;
        }
    plat_mutex_unlock(&g.lock);
    return r;
}

void xwlan_get(xwlan_set *s)
{
    if (!g.on) {
        memset(s, 0, sizeof(*s));
        return;
    }
    plat_mutex_lock(&g.lock);
    *s = g.set;
    plat_mutex_unlock(&g.lock);
}

#ifdef __linux__
#  include <errno.h>
#  include <sys/socket.h>
#  include <sys/time.h>
#  include <unistd.h>

#  ifndef AF_NETLINK
#    define AF_NETLINK 16
#  endif
#  define NETLINK_GENERIC_ 16
#  define NLM_F_REQUEST_ 1
#  define NLM_F_DUMP_ 0x300
#  define RX 65536

struct sockaddr_nl_ {
    sa_family_t nl_family;
    unsigned short nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};

typedef int (*parse_fn)(const uint8_t *b, size_t n, uint32_t seq, void *out, int *err);

static int p_family(const uint8_t *b, size_t n, uint32_t seq, void *out, int *err)
{
    return xwlan_parse_family(b, n, seq, out, err);
}
static int p_ifaces(const uint8_t *b, size_t n, uint32_t seq, void *out, int *err)
{
    return xwlan_parse_ifaces(b, n, seq, out, err);
}
static int p_scan(const uint8_t *b, size_t n, uint32_t seq, void *out, int *err)
{
    return xwlan_parse_scan(b, n, seq, out, err);
}

/* one request and its answers (the socket waits at most a second) */
static int transact(uint16_t family, uint16_t flags, uint8_t cmd, uint16_t attr, const void *d, size_t len,
                    parse_fn fn, void *out, int *err)
{
    static uint8_t rx[RX];
    uint8_t req[64];
    struct sockaddr_nl_ sa;
    uint32_t seq = ++g.seq;
    size_t n = xwlan_build(req, sizeof(req), family, flags, seq, cmd, attr, d, len);
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    *err = 0;
    if (sendto(g.fd, req, n, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        *err = errno;
        return -1;
    }
    for (;;) {
        ssize_t r = recv(g.fd, rx, sizeof(rx), 0);
        int rc;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            *err = errno;
            return -1;
        }
        rc = fn(rx, (size_t)r, seq, out, err);
        if (rc)
            return rc < 0 ? -1 : 0;
    }
}

int xwlan_init(sbuf *err)
{
    struct sockaddr_nl_ sa;
    struct timeval tv = {1, 0};
    int e = 0;
    xwlan_free();
    g.fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC_);
    if (g.fd < 0) {
        sb_printf(err, "--filter-ssid: generic netlink socket: %s", strerror(errno));
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    setsockopt(g.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (bind(g.fd, (struct sockaddr *)&sa, sizeof(sa)) < 0 ||
        transact(GENL_ID_CTRL_, NLM_F_REQUEST_, CTRL_CMD_GETFAMILY_, CTRL_ATTR_FAMILY_NAME_, "nl80211", 8, p_family,
                 &g.family, &e) < 0 ||
        !g.family) {
        sb_printf(err, "--filter-ssid: no nl80211 (Wi-Fi) in this kernel: %s", e ? strerror(e) : "no family id");
        close(g.fd);
        g.fd = -1;
        return -1;
    }
    plat_mutex_init(&g.lock);
    g.on = 1;
    g.last_sec = 0;
    g.busy = 0;
    memset(&g.set, 0, sizeof(g.set));
    xwlan_refresh(plat_now_ms());
    return 0;
}

void xwlan_free(void)
{
    if (g.fd >= 0)
        close(g.fd);
    g.fd = -1;
    if (g.on)
        plat_mutex_destroy(&g.lock);
    g.on = 0;
}

static int read_set(xwlan_set *s)
{
    int e;
    memset(s, 0, sizeof(*s));
    if (transact(g.family, NLM_F_REQUEST_ | NLM_F_DUMP_, CMD_GET_INTERFACE, 0, NULL, 0, p_ifaces, s, &e) < 0) {
        LOGD("wlan", "GET_INTERFACE: %s", strerror(e));
        return -1;
    }
    for (int i = 0; i < s->n; i++) {
        uint32_t idx = s->v[i].ifindex;
        if (transact(g.family, NLM_F_REQUEST_ | NLM_F_DUMP_, CMD_GET_SCAN, ATTR_IFINDEX, &idx, 4, p_scan, s, &e) < 0)
            LOGD("wlan", "GET_SCAN %s: %s", s->v[i].ifname, strerror(e));
    }
    return 0;
}

void xwlan_refresh(uint64_t now_ms)
{
    xwlan_set s;
    uint64_t sec = now_ms / 1000 + 1;
    if (!g.on)
        return;
    plat_mutex_lock(&g.lock);
    if (g.busy || g.last_sec == sec) {
        plat_mutex_unlock(&g.lock);
        return;
    }
    g.busy = 1;
    g.last_sec = sec;
    plat_mutex_unlock(&g.lock);
    if (read_set(&s) < 0) {
        plat_mutex_lock(&g.lock);
        g.busy = 0;
        plat_mutex_unlock(&g.lock);
        return;
    }
    plat_mutex_lock(&g.lock);
    for (int i = 0; i < s.n; i++) {
        const char *old = "";
        for (int k = 0; k < g.set.n; k++)
            if (g.set.v[k].ifindex == s.v[i].ifindex)
                old = g.set.v[k].ssid;
        if (strcmp(old, s.v[i].ssid))
            LOGI("wlan", "%s: %s%s%s", s.v[i].ifname, s.v[i].ssid[0] ? "SSID \"" : "not connected",
                 s.v[i].ssid, s.v[i].ssid[0] ? "\"" : "");
    }
    g.set = s;
    g.busy = 0;
    plat_mutex_unlock(&g.lock);
}

#else

int xwlan_init(sbuf *err)
{
    sb_puts(err, "--filter-ssid is Linux-only (nl80211); on Windows --ssid-filter and --nlm-filter");
    return -1;
}

void xwlan_free(void) { g.on = 0; }

void xwlan_refresh(uint64_t now_ms) { (void)now_ms; }

#endif
