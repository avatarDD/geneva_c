/*
 * Windows packet backend: WinDivert (https://reqrypt.org/windivert.html).
 *
 * WinDivert.dll is loaded at run time from the directory of geneva.exe, next
 * to the WinDivert64.sys (or WinDivert32.sys) driver from the official
 * release; nothing else is needed to build. The few declarations used here
 * follow windivert.h of WinDivert 2.x.
 *
 * A receiver thread blocks in WinDivertRecv() and runs every packet through
 * the engine under e->lock. Results leave through WinDivertSend() with the
 * captured packet's address, so they go the same way (outbound or inbound,
 * same interface). Delayed packets are released by the main loop, which the
 * receiver wakes through a loopback UDP socket when it queues one.
 */
#include "engine_int.h"

#ifdef _WIN32

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "geneva.h"
#include "log.h"

/* ---- WinDivert 2.x ABI --------------------------------------------------- */

#define WD_LAYER_NETWORK 0
#define WD_PARAM_QUEUE_LENGTH 0
#define WD_PARAM_QUEUE_TIME 1
#define WD_PARAM_QUEUE_SIZE 2
#define WD_SHUTDOWN_RECV 1

/* WINDIVERT_ADDRESS: 80 bytes. The bitfield word is handled by hand so the
 * layout does not depend on the compiler's bitfield rules. */
typedef struct {
    INT64 timestamp;
    UINT32 bits;
    UINT32 reserved2;
    union {
        struct {
            UINT32 if_idx, sub_if_idx;
        } network;
        UINT8 reserved3[64];
    } u;
} wd_address;

#define WD_OUTBOUND (1u << 17)
#define WD_IPV6 (1u << 20)
#define WD_IP_CSUM (1u << 21)
#define WD_TCP_CSUM (1u << 22)
#define WD_UDP_CSUM (1u << 23)
#define WD_ALL_CSUM (WD_IP_CSUM | WD_TCP_CSUM | WD_UDP_CSUM)

typedef HANDLE(__cdecl *wd_open_fn)(const char *filter, int layer, INT16 priority, UINT64 flags);
typedef BOOL(__cdecl *wd_recv_fn)(HANDLE h, void *pkt, UINT len, UINT *recv_len, wd_address *addr);
typedef BOOL(__cdecl *wd_send_fn)(HANDLE h, const void *pkt, UINT len, UINT *send_len, const wd_address *addr);
typedef BOOL(__cdecl *wd_shutdown_fn)(HANDLE h, int how);
typedef BOOL(__cdecl *wd_close_fn)(HANDLE h);
typedef BOOL(__cdecl *wd_setparam_fn)(HANDLE h, int param, UINT64 value);
typedef BOOL(__cdecl *wd_csum_fn)(void *pkt, UINT len, wd_address *addr, UINT64 flags);

typedef struct {
    HMODULE dll;
    wd_open_fn open;
    wd_recv_fn recv;
    wd_send_fn send;
    wd_shutdown_fn shutdown;
    wd_close_fn close;
    wd_setparam_fn setparam;
    wd_csum_fn csum;
    HANDLE h;
    plat_thread_t thread;
    int thread_on;
    volatile LONG stopping;
    volatile LONG failed; /* the receiver hit an error it cannot recover from */
    DWORD fail_code;
    sock_t wake_rx, wake_tx;
} wd_state;

#define WD_MAX_PACKET 65575 /* 0xFFFF + an IPv6 header */

/* ---- helpers ------------------------------------------------------------- */

static void win_error(sbuf *out, DWORD code)
{
    char msg[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                             MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), msg, sizeof(msg), NULL);
    while (n && (msg[n - 1] == '\r' || msg[n - 1] == '\n' || msg[n - 1] == '.'))
        msg[--n] = 0;
    sb_printf(out, "error %lu%s%s", (unsigned long)code, n ? ": " : "", n ? msg : "");
}

/* Loads WinDivert.dll from the directory of the executable only, so that a
 * DLL planted in the current directory or on PATH is never picked up. */
static int load_dll(wd_state *s, sbuf *err)
{
    wchar_t path[MAX_PATH + 32];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t *slash;
    if (!n || n >= MAX_PATH) {
        sb_puts(err, "cannot find the directory of geneva.exe");
        return -1;
    }
    slash = wcsrchr(path, L'\\');
    if (!slash) {
        sb_puts(err, "cannot find the directory of geneva.exe");
        return -1;
    }
    wcscpy(slash + 1, L"WinDivert.dll");
    s->dll = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!s->dll) {
        sb_puts(err, "cannot load WinDivert.dll from the directory of geneva.exe (");
        win_error(err, GetLastError());
        sb_puts(err, "); put WinDivert.dll and WinDivert64.sys from the official WinDivert 2.x "
                     "release (https://github.com/basil00/WinDivert/releases) next to geneva.exe");
        return -1;
    }
#define LOAD(field, type, name)                                                                     \
    if (!(s->field = (type)(void (*)(void))GetProcAddress(s->dll, name))) {                         \
        sb_printf(err, "WinDivert.dll has no %s (need WinDivert 2.x)", name);                       \
        return -1;                                                                                  \
    }
    LOAD(open, wd_open_fn, "WinDivertOpen");
    LOAD(recv, wd_recv_fn, "WinDivertRecv");
    LOAD(send, wd_send_fn, "WinDivertSend");
    LOAD(shutdown, wd_shutdown_fn, "WinDivertShutdown");
    LOAD(close, wd_close_fn, "WinDivertClose");
    LOAD(setparam, wd_setparam_fn, "WinDivertSetParam");
    LOAD(csum, wd_csum_fn, "WinDivertHelperCalcChecksums");
#undef LOAD
    return 0;
}

/* A connected loopback UDP pair: the receiver thread sends a byte to wake
 * the main loop's WSAPoll. */
static int wake_open(wd_state *s, sbuf *err)
{
    struct sockaddr_in a;
    int alen = sizeof(a);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    s->wake_rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    s->wake_tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s->wake_rx == SOCK_INVALID || s->wake_tx == SOCK_INVALID ||
        bind(s->wake_rx, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockname(s->wake_rx, (struct sockaddr *)&a, &alen) != 0 ||
        connect(s->wake_tx, (struct sockaddr *)&a, sizeof(a)) != 0) {
        sb_printf(err, "wake socket: %s", plat_sock_strerror(plat_sock_err()));
        return -1;
    }
    plat_sock_nonblock(s->wake_rx, 1);
    plat_sock_nonblock(s->wake_tx, 1);
    return 0;
}

static void wake(wd_state *s)
{
    char b = 1;
    send(s->wake_tx, &b, 1, 0); /* a full buffer already means "wake up" */
}

/* ---- backend ------------------------------------------------------------- */

static int wd_send_pkt(engine *e, const wd_address *orig, const uint8_t *data, size_t len, int exact)
{
    wd_state *s = e->bs;
    wd_address a = *orig;
    UINT sent = 0;
    if (exact) {
        /* our bytes carry the checksums we want (even broken ones): tell
         * WinDivert they are valid so that it does not touch them */
        a.bits |= WD_ALL_CSUM;
        if (len && (data[0] >> 4) == 6)
            a.bits |= WD_IPV6;
        else
            a.bits &= ~WD_IPV6;
    }
    if (!s->send(s->h, data, (UINT)len, &sent, &a)) {
        if (log_enabled(LOG_DEBUG)) {
            sbuf m;
            sb_init(&m);
            win_error(&m, GetLastError());
            LOGD("engine", "WinDivertSend: %s", m.data);
            sb_free(&m);
        }
        return -1;
    }
    return 0;
}

/* pctx is the packet's wd_address followed by its original bytes when the
 * verdict keeps them (data == NULL): the core holds no copy of those. */
typedef struct {
    wd_address addr;
    const uint8_t *data;
    size_t len;
} wd_pctx;

static int wd_be_verdict(engine *e, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    const wd_pctx *p = pctx;
    if (!accept)
        return 0; /* not sending is dropping */
    if (!data) {
        if (!p->data) {
            LOGW("engine", "lost the bytes of a delayed packet");
            return -1;
        }
        return wd_send_pkt(e, &p->addr, p->data, p->len, 0);
    }
    return wd_send_pkt(e, &p->addr, data, len, 1);
}

static int wd_be_inject(engine *e, const void *pctx, const uint8_t *data, size_t len)
{
    const wd_pctx *p = pctx;
    return wd_send_pkt(e, &p->addr, data, len, 1);
}

static void receiver(void *arg)
{
    engine *e = arg;
    wd_state *s = e->bs;
    uint8_t *buf = xmalloc(WD_MAX_PACKET);
    for (;;) {
        wd_pctx p;
        UINT n = 0;
        uint64_t before;
        memset(&p, 0, sizeof(p));
        if (!s->recv(s->h, buf, WD_MAX_PACKET, &n, &p.addr)) {
            DWORD code = GetLastError();
            if (code == ERROR_NO_DATA || InterlockedCompareExchange(&s->stopping, 0, 0))
                break; /* shut down and drained */
            if (code == ERROR_INSUFFICIENT_BUFFER) {
                LOGW("engine", "dropped a packet larger than %d bytes", WD_MAX_PACKET);
                continue;
            }
            s->fail_code = code;
            InterlockedExchange(&s->failed, 1);
            wake(s);
            break;
        }
        /* outbound packets may come with offloaded (unfinished) checksums:
         * complete them, so that copies and exact sends carry valid ones */
        if ((p.addr.bits & WD_ALL_CSUM) != WD_ALL_CSUM)
            s->csum(buf, n, &p.addr, 0);
        p.data = buf;
        p.len = n;
        plat_mutex_lock(&e->lock);
        before = e->dl_order;
        engine_packet(e, buf, n, (p.addr.bits & WD_OUTBOUND) ? DIR_OUT : DIR_IN, &p);
        if (e->dl_order != before) {
            /* delayed packets keep a copy of pctx: its pointer to this
             * buffer must not outlive the packet (they carry their own
             * bytes anyway); then wake the main loop for the new timer */
            for (size_t i = 0; i < e->ndl; i++) {
                wd_pctx *q = (wd_pctx *)e->dl[i].pctx;
                if (q->data == buf)
                    q->data = NULL;
            }
            wake(s);
        }
        plat_mutex_unlock(&e->lock);
    }
    free(buf);
}

static int wd_be_open(engine *e, sbuf *err)
{
    engine_opts *o = e->o;
    wd_state *s = xcalloc(1, sizeof(*s));
    sbuf filter;
    DWORD code;

    s->wake_rx = s->wake_tx = SOCK_INVALID;
    s->h = INVALID_HANDLE_VALUE;
    e->bs = s;
    e->err_where = "windivert";
    sb_init(&filter);
    if (fw_windivert_filter(&o->fw, &filter, err) < 0) {
        sb_free(&filter);
        return EXIT_USAGE;
    }
    LOGD("engine", "WinDivert filter: %s", filter.data);
    if (load_dll(s, err) < 0 || wake_open(s, err) < 0) {
        sb_free(&filter);
        return EXIT_FAIL;
    }
    s->h = s->open(filter.data, WD_LAYER_NETWORK, 0, 0);
    code = GetLastError();
    sb_free(&filter);
    if (s->h == INVALID_HANDLE_VALUE) {
        sb_puts(err, "WinDivertOpen: ");
        win_error(err, code);
        switch (code) {
        case ERROR_ACCESS_DENIED:
            sb_puts(err, " (run as Administrator)");
            return EXIT_PRIV;
        case ERROR_FILE_NOT_FOUND:
            sb_puts(err, " (WinDivert64.sys or WinDivert32.sys must be next to WinDivert.dll)");
            return EXIT_FAIL;
        case ERROR_INVALID_IMAGE_HASH:
            sb_puts(err, " (the driver signature was rejected: use the official WinDivert release)");
            return EXIT_FAIL;
        case ERROR_INVALID_PARAMETER:
            sb_puts(err, " (bad filter)");
            return EXIT_FAIL;
        }
        return EXIT_FAIL;
    }
    {
        UINT64 qlen = o->queue_maxlen < 32 ? 32 : o->queue_maxlen > 16384 ? 16384 : o->queue_maxlen;
        if (!s->setparam(s->h, WD_PARAM_QUEUE_LENGTH, qlen))
            LOGW("engine", "WinDivertSetParam(QUEUE_LENGTH) failed");
        s->setparam(s->h, WD_PARAM_QUEUE_SIZE, 16u << 20);
    }
    if (plat_thread_start(&s->thread, receiver, e) != 0) {
        sb_puts(err, "cannot start the receiver thread");
        return EXIT_FAIL;
    }
    s->thread_on = 1;
    e->fw_name = "windivert";
    e->err_where = NULL;
    LOGI("engine", "capturing with WinDivert");
    return EXIT_OK;
}

static void wd_be_stop(engine *e)
{
    wd_state *s = e->bs;
    if (!s || s->h == INVALID_HANDLE_VALUE)
        return;
    /* no new packets; the receiver handles the queued ones, then stops */
    InterlockedExchange(&s->stopping, 1);
    s->shutdown(s->h, WD_SHUTDOWN_RECV);
    if (s->thread_on) {
        plat_thread_join(s->thread);
        s->thread_on = 0;
    }
}

static void wd_be_close(engine *e)
{
    wd_state *s = e->bs;
    if (!s)
        return;
    if (s->h != INVALID_HANDLE_VALUE) {
        if (s->thread_on) { /* stop() was not called */
            s->shutdown(s->h, WD_SHUTDOWN_RECV);
            plat_thread_join(s->thread);
        }
        s->close(s->h);
    }
    if (s->wake_rx != SOCK_INVALID)
        plat_sock_close(s->wake_rx);
    if (s->wake_tx != SOCK_INVALID)
        plat_sock_close(s->wake_tx);
    if (s->dll)
        FreeLibrary(s->dll);
    free(s);
    e->bs = NULL;
}

static size_t wd_be_pollfds(engine *e, plat_pollfd *fds, size_t max)
{
    wd_state *s = e->bs;
    if (!max)
        return 0;
    fds[0].fd = s->wake_rx;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return 1;
}

static int wd_be_ready(engine *e, const plat_pollfd *fds, size_t n)
{
    wd_state *s = e->bs;
    if (n && (fds[0].revents & POLLIN)) {
        char b[64];
        while (recv(s->wake_rx, b, sizeof(b), 0) > 0)
            ;
    }
    if (InterlockedCompareExchange(&s->failed, 0, 0)) {
        sbuf m;
        sb_init(&m);
        win_error(&m, s->fail_code);
        LOGE("engine", "WinDivertRecv: %s", m.data);
        sb_free(&m);
        return -1;
    }
    return 0;
}

const backend windivert_backend = {
    "windivert",
    sizeof(wd_pctx),
    wd_be_open,
    wd_be_stop,
    wd_be_close,
    wd_be_pollfds,
    wd_be_ready,
    wd_be_verdict,
    wd_be_inject,
};

#endif
