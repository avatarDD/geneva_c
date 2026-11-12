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
typedef BOOL(__cdecl *wd_compile_fn)(const char *filter, int layer, char *object, UINT obj_len,
                                     const char **error_str, UINT *error_pos);

typedef struct {
    HMODULE dll;
    wd_open_fn open;
    wd_recv_fn recv;
    wd_send_fn send;
    wd_shutdown_fn shutdown;
    wd_close_fn close;
    wd_setparam_fn setparam;
    wd_csum_fn csum;
    wd_compile_fn compile;
    HANDLE h;       /* the newest handle: results are sent through it */
    HANDLE rx;      /* the handle the receiver reads */
    HANDLE rx_next; /* set_filter: the receiver moves here once rx is drained */
    plat_mutex_t hlock; /* rx and rx_next */
    sbuf filter;    /* the filter of h */
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
    LOAD(compile, wd_compile_fn, "WinDivertHelperCompileFilter");
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

static int wd_be_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    engine *e = w->e;
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

static int wd_be_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    const wd_pctx *p = pctx;
    return wd_send_pkt(w->e, &p->addr, data, len, 1);
}

static void receiver(void *arg)
{
    engine *e = arg;
    wd_state *s = e->bs;
    eng_worker *w = &e->w[0]; /* one handle, one worker */
    uint8_t *buf = xmalloc(WD_MAX_PACKET);
    for (;;) {
        wd_pctx p;
        UINT n = 0;
        uint64_t before;
        memset(&p, 0, sizeof(p));
        if (!s->recv(s->rx, buf, WD_MAX_PACKET, &n, &p.addr)) {
            DWORD code = GetLastError();
            if (code == ERROR_NO_DATA) {
                /* shut down and drained: by set_filter (go on with the
                 * new handle) or by stop */
                HANDLE old = s->rx, next;
                plat_mutex_lock(&s->hlock);
                next = s->rx_next;
                if (next) {
                    s->rx = next;
                    s->rx_next = NULL;
                }
                plat_mutex_unlock(&s->hlock);
                if (!next)
                    break;
                s->close(old);
                LOGD("engine", "the previous filter's packets are done, its handle is closed");
                continue;
            }
            if (InterlockedCompareExchange(&s->stopping, 0, 0))
                break;
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
        before = w->dl_order;
        engine_packet(w, buf, n, (p.addr.bits & WD_OUTBOUND) ? DIR_OUT : DIR_IN, &p);
        if (w->dl_order != before) {
            /* delayed packets keep a copy of pctx: its pointer to this
             * buffer must not outlive the packet (they carry their own
             * bytes anyway); then wake the main loop for the new timer */
            for (size_t i = 0; i < w->ndl; i++) {
                wd_pctx *q = (wd_pctx *)w->dl[i].pctx;
                if (q->data == buf)
                    q->data = NULL;
            }
            wake(s);
        }
        plat_mutex_unlock(&e->lock);
    }
    free(buf);
}

/* Checks that expr compiles for the network layer. */
static int wd_check(wd_state *s, const char *expr, sbuf *err, int *pos)
{
    const char *es = NULL;
    UINT ep = 0;
    if (s->compile(expr, WD_LAYER_NETWORK, NULL, 0, &es, &ep))
        return 0;
    sb_printf(err, "the filter does not compile at position %u: %s", (unsigned)ep, es ? es : "error");
    if (pos)
        *pos = (int)ep;
    return -1;
}

/* Opens a handle with the engine's priority and queue settings. Returns
 * INVALID_HANDLE_VALUE with a message and an exit code in *rc. */
static HANDLE wd_open_handle(engine *e, const char *filter, sbuf *err, int *rc)
{
    wd_state *s = e->bs;
    engine_opts *o = e->o;
    HANDLE h = s->open(filter, WD_LAYER_NETWORK, (INT16)o->fw.priority, 0);
    DWORD code = GetLastError();
    if (h == INVALID_HANDLE_VALUE) {
        sb_puts(err, "WinDivertOpen: ");
        win_error(err, code);
        *rc = EXIT_FAIL;
        switch (code) {
        case ERROR_ACCESS_DENIED:
            sb_puts(err, " (run as Administrator)");
            *rc = EXIT_PRIV;
            break;
        case ERROR_FILE_NOT_FOUND:
            sb_puts(err, " (WinDivert64.sys or WinDivert32.sys must be next to WinDivert.dll)");
            break;
        case ERROR_INVALID_IMAGE_HASH:
            sb_puts(err, " (the driver signature was rejected: use the official WinDivert release)");
            break;
        case ERROR_INVALID_PARAMETER:
            sb_puts(err, " (bad filter)");
            break;
        }
        return h;
    }
    {
        UINT64 qlen = o->queue_maxlen < 32 ? 32 : o->queue_maxlen > 16384 ? 16384 : o->queue_maxlen;
        if (!s->setparam(h, WD_PARAM_QUEUE_LENGTH, qlen))
            LOGW("engine", "WinDivertSetParam(QUEUE_LENGTH) failed");
        s->setparam(h, WD_PARAM_QUEUE_SIZE, 16u << 20);
    }
    *rc = EXIT_OK;
    return h;
}

static int wd_be_open(engine *e, sbuf *err)
{
    engine_opts *o = e->o;
    wd_state *s = xcalloc(1, sizeof(*s));
    int rc;

    s->wake_rx = s->wake_tx = SOCK_INVALID;
    s->h = s->rx = INVALID_HANDLE_VALUE;
    plat_mutex_init(&s->hlock);
    sb_init(&s->filter);
    e->bs = s;
    e->err_where = "windivert";
    if (fw_windivert_filter(&o->fw, &s->filter, err) < 0) {
        e->err_where = "filter";
        return EXIT_USAGE;
    }
    LOGD("engine", "WinDivert filter: %s", s->filter.data);
    if (load_dll(s, err) < 0 || wake_open(s, err) < 0)
        return EXIT_FAIL;
    if (o->fw.filter) {
        /* the caller's expression: its own errors, at its own positions */
        int pos = -1;
        if (wd_check(s, o->fw.filter, err, &pos) < 0 || wd_check(s, s->filter.data, err, NULL) < 0) {
            e->err_where = "filter";
            e->err_pos = pos;
            return EXIT_USAGE;
        }
    }
    s->h = wd_open_handle(e, s->filter.data, err, &rc);
    if (s->h == INVALID_HANDLE_VALUE)
        return rc;
    s->rx = s->h;
    if (plat_thread_start(&s->thread, receiver, e) != 0) {
        sb_puts(err, "cannot start the receiver thread");
        return EXIT_FAIL;
    }
    s->thread_on = 1;
    e->fw_name = "windivert";
    e->err_where = NULL;
    LOGI("engine", "capturing with WinDivert (priority %d)", o->fw.priority);
    return EXIT_OK;
}

/* set_filter: a new handle takes over. The old one stops queueing, the
 * receiver handles what it holds and then moves to the new one; a packet is
 * diverted once per priority level, so none is seen by both. */
static int wd_be_set_filter(engine *e, const char *expr, sbuf *out, sbuf *err, int *pos)
{
    wd_state *s = e->bs;
    sbuf f;
    HANDLE h2, old;
    int rc;

    sb_init(&f);
    if (fw_windivert_filter_expr(&e->o->fw, expr, &f, err) < 0)
        goto fail;
    if (wd_check(s, expr, err, pos) < 0 || wd_check(s, f.data, err, NULL) < 0)
        goto fail;
    for (ULONGLONG deadline = GetTickCount64() + 2000;;) {
        HANDLE pending;
        plat_mutex_lock(&s->hlock);
        pending = s->rx_next;
        plat_mutex_unlock(&s->hlock);
        if (!pending)
            break;
        if (GetTickCount64() >= deadline || InterlockedCompareExchange(&s->failed, 0, 0)) {
            sb_puts(err, "the previous filter change is still in progress");
            goto fail;
        }
        /* the receiver needs the lock to finish the old handle's packets */
        plat_mutex_unlock(&e->lock);
        Sleep(1);
        plat_mutex_lock(&e->lock);
    }
    h2 = wd_open_handle(e, f.data, err, &rc);
    if (h2 == INVALID_HANDLE_VALUE)
        goto fail;
    plat_mutex_lock(&s->hlock);
    old = s->rx;
    s->rx_next = h2;
    s->h = h2; /* results and delayed packets leave through the new handle */
    s->shutdown(old, WD_SHUTDOWN_RECV);
    plat_mutex_unlock(&s->hlock);
    sb_reset(&s->filter);
    sb_puts(&s->filter, f.data);
    sb_puts(out, f.data);
    sb_free(&f);
    LOGD("engine", "WinDivert filter: %s", s->filter.data);
    return 0;
fail:
    sb_free(&f);
    return -1;
}

static const char *wd_be_filter(engine *e)
{
    wd_state *s = e->bs;
    return s && s->filter.len ? s->filter.data : NULL;
}

static void wd_be_stop(engine *e)
{
    wd_state *s = e->bs;
    if (!s || s->rx == INVALID_HANDLE_VALUE)
        return;
    /* no new packets; the receiver handles the queued ones, then stops */
    InterlockedExchange(&s->stopping, 1);
    plat_mutex_lock(&s->hlock);
    s->shutdown(s->rx, WD_SHUTDOWN_RECV);
    if (s->rx_next)
        s->shutdown(s->rx_next, WD_SHUTDOWN_RECV);
    plat_mutex_unlock(&s->hlock);
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
    if (s->rx != INVALID_HANDLE_VALUE) {
        if (s->thread_on) /* stop() was not called */
            wd_be_stop(e);
        s->close(s->rx);
        if (s->rx_next) /* the receiver died before it moved */
            s->close(s->rx_next);
    }
    sb_free(&s->filter);
    plat_mutex_destroy(&s->hlock);
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
    1, /* --first: no conntrack, the engine counts */
    wd_be_filter,
    wd_be_set_filter,
    NULL, /* meta: not yet */
    NULL, /* inject_x: no marks or interfaces, x-action packets go through inject */
    NULL, /* detach: WinDivert keeps a copy, the stack is not held up */
    NULL, /* worker_fd: one handle (--ext-workers is Linux only for now) */
    NULL,
};

#endif
