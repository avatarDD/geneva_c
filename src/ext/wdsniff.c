/*
 * --ext-auto's observation through a WinDivert SNIFF handle (wdsniff.h).
 */
#include "wdsniff.h"

#ifdef _WIN32

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "log.h"

/* WinDivert 2.x, as in windivert.h (src/eng_windivert.c has the engine's
 * part of the same ABI) */
#define WD_LAYER_NETWORK 0
#define WD_FLAG_SNIFF 0x0001
#define WD_FLAG_RECV_ONLY 0x0004
#define WD_PARAM_QUEUE_LENGTH 0
#define WD_PARAM_QUEUE_SIZE 2
#define WD_SHUTDOWN_BOTH 3
#define WD_OUTBOUND (1u << 17)
#define WD_MAX_PACKET 65575

typedef struct {
    INT64 timestamp;
    UINT32 bits;
    UINT32 reserved2;
    UINT8 reserved3[64];
} wd_address;

typedef HANDLE(__cdecl *wd_open_fn)(const char *filter, int layer, INT16 priority, UINT64 flags);
typedef BOOL(__cdecl *wd_recv_fn)(HANDLE h, void *pkt, UINT len, UINT *recv_len, wd_address *addr);
typedef BOOL(__cdecl *wd_shutdown_fn)(HANDLE h, int how);
typedef BOOL(__cdecl *wd_close_fn)(HANDLE h);
typedef BOOL(__cdecl *wd_setparam_fn)(HANDLE h, int param, UINT64 value);

#define SLOTS 2048 /* packets the ring holds */

typedef struct {
    uint16_t len;
    uint8_t out;
} slot_hdr;

struct wdsniff {
    HMODULE dll;
    wd_open_fn open;
    wd_recv_fn recv;
    wd_shutdown_fn shutdown;
    wd_close_fn close;
    wd_setparam_fn setparam;
    HANDLE h;
    plat_thread_t thread;
    int thread_on;
    volatile LONG stopping, failed;
    DWORD fail_code;
    sock_t wake_rx, wake_tx;
    plat_mutex_t lock; /* the ring */
    uint32_t range;
    size_t stride;
    uint8_t *ring;
    size_t head, count;
    uint64_t lost;
};

static void win_error(sbuf *out, DWORD code)
{
    char msg[256];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, code,
                             MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), msg, sizeof(msg), NULL);
    while (n && (msg[n - 1] == '\r' || msg[n - 1] == '\n' || msg[n - 1] == '.'))
        msg[--n] = 0;
    sb_printf(out, "error %lu%s%s", (unsigned long)code, n ? ": " : "", n ? msg : "");
}

/* WinDivert.dll from the directory of geneva.exe only, as the engine */
static int load_dll(wdsniff *s, sbuf *err)
{
    wchar_t path[MAX_PATH + 32];
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);
    wchar_t *slash = n && n < MAX_PATH ? wcsrchr(path, L'\\') : NULL;
    if (!slash) {
        sb_puts(err, "cannot find the directory of geneva.exe");
        return -1;
    }
    wcscpy(slash + 1, L"WinDivert.dll");
    s->dll = LoadLibraryExW(path, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
    if (!s->dll) {
        sb_puts(err, "cannot load WinDivert.dll from the directory of geneva.exe (");
        win_error(err, GetLastError());
        sb_puts(err, ")");
        return -1;
    }
#define LOAD(field, type, name)                                                                     \
    if (!(s->field = (type)(void (*)(void))GetProcAddress(s->dll, name))) {                         \
        sb_printf(err, "WinDivert.dll has no %s (need WinDivert 2.x)", name);                       \
        return -1;                                                                                  \
    }
    LOAD(open, wd_open_fn, "WinDivertOpen");
    LOAD(recv, wd_recv_fn, "WinDivertRecv");
    LOAD(shutdown, wd_shutdown_fn, "WinDivertShutdown");
    LOAD(close, wd_close_fn, "WinDivertClose");
    LOAD(setparam, wd_setparam_fn, "WinDivertSetParam");
#undef LOAD
    return 0;
}

static int wake_open(wdsniff *s, sbuf *err)
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

static void wake(wdsniff *s)
{
    char b = 1;
    send(s->wake_tx, &b, 1, 0); /* a full buffer already means "wake up" */
}

static void receiver(void *arg)
{
    wdsniff *s = arg;
    uint8_t *buf = xmalloc(WD_MAX_PACKET);
    for (;;) {
        wd_address addr;
        UINT n = 0;
        int was_empty = 0;
        if (!s->recv(s->h, buf, WD_MAX_PACKET, &n, &addr)) {
            DWORD code = GetLastError();
            if (code == ERROR_NO_DATA || InterlockedCompareExchange(&s->stopping, 0, 0))
                break;
            if (code == ERROR_INSUFFICIENT_BUFFER)
                continue;
            s->fail_code = code;
            InterlockedExchange(&s->failed, 1);
            wake(s);
            break;
        }
        plat_mutex_lock(&s->lock);
        if (s->count == SLOTS) {
            s->lost++;
        } else {
            uint8_t *p = s->ring + ((s->head + s->count) % SLOTS) * s->stride;
            slot_hdr hd;
            hd.len = (uint16_t)(n < s->range ? n : s->range);
            hd.out = (addr.bits & WD_OUTBOUND) != 0;
            memcpy(p, &hd, sizeof(hd));
            memcpy(p + sizeof(hd), buf, hd.len);
            was_empty = s->count++ == 0;
        }
        plat_mutex_unlock(&s->lock);
        if (was_empty)
            wake(s);
    }
    free(buf);
}

wdsniff *wdsniff_open(int priority, uint32_t range, sbuf *err, int *priv)
{
    wdsniff *s = xcalloc(1, sizeof(*s));
    DWORD code;
    *priv = 0;
    s->wake_rx = s->wake_tx = SOCK_INVALID;
    s->h = INVALID_HANDLE_VALUE;
    plat_mutex_init(&s->lock);
    s->range = range < 64 ? 64 : range > 0xffff ? 0xffff : range;
    s->stride = sizeof(slot_hdr) + s->range;
    s->ring = xmalloc(SLOTS * s->stride);
    if (load_dll(s, err) < 0 || wake_open(s, err) < 0)
        goto fail;
    s->h = s->open(WDSNIFF_FILTER, WD_LAYER_NETWORK, (INT16)(priority < -30000 ? -30000 : priority > 30000 ? 30000 : priority),
                   WD_FLAG_SNIFF | WD_FLAG_RECV_ONLY);
    code = GetLastError();
    if (s->h == INVALID_HANDLE_VALUE) {
        sb_puts(err, "WinDivertOpen (sniff): ");
        win_error(err, code);
        *priv = code == ERROR_ACCESS_DENIED;
        goto fail;
    }
    s->setparam(s->h, WD_PARAM_QUEUE_LENGTH, 16384);
    s->setparam(s->h, WD_PARAM_QUEUE_SIZE, 8u << 20);
    if (plat_thread_start(&s->thread, receiver, s) != 0) {
        sb_puts(err, "cannot start the sniff thread");
        goto fail;
    }
    s->thread_on = 1;
    return s;
fail:
    wdsniff_close(s);
    return NULL;
}

void wdsniff_close(wdsniff *s)
{
    if (!s)
        return;
    InterlockedExchange(&s->stopping, 1);
    if (s->h != INVALID_HANDLE_VALUE)
        s->shutdown(s->h, WD_SHUTDOWN_BOTH);
    if (s->thread_on)
        plat_thread_join(s->thread);
    if (s->h != INVALID_HANDLE_VALUE)
        s->close(s->h);
    if (s->dll)
        FreeLibrary(s->dll);
    if (s->wake_rx != SOCK_INVALID)
        plat_sock_close(s->wake_rx);
    if (s->wake_tx != SOCK_INVALID)
        plat_sock_close(s->wake_tx);
    plat_mutex_destroy(&s->lock);
    free(s->ring);
    free(s);
}

sock_t wdsniff_fd(const wdsniff *s) { return s->wake_rx; }

int wdsniff_read(wdsniff *s, size_t max, wdsniff_cb cb, void *ctx, uint64_t *lost)
{
    char junk[64];
    uint8_t *buf = xmalloc(s->stride);
    int n = 0;
    while (recv(s->wake_rx, junk, sizeof(junk), 0) > 0)
        ;
    for (; (size_t)n < max; n++) {
        slot_hdr hd;
        plat_mutex_lock(&s->lock);
        if (!s->count) {
            plat_mutex_unlock(&s->lock);
            break;
        }
        memcpy(buf, s->ring + s->head * s->stride, s->stride);
        s->head = (s->head + 1) % SLOTS;
        s->count--;
        plat_mutex_unlock(&s->lock);
        memcpy(&hd, buf, sizeof(hd));
        cb(buf + sizeof(hd), hd.len, hd.out, ctx);
    }
    plat_mutex_lock(&s->lock);
    *lost += s->lost;
    s->lost = 0;
    if (s->count)
        wake(s); /* more than max: the next poll comes back at once */
    plat_mutex_unlock(&s->lock);
    free(buf);
    if (InterlockedCompareExchange(&s->failed, 0, 0)) {
        LOGW("auto", "WinDivert sniff: error %lu", (unsigned long)s->fail_code);
        return -1;
    }
    return n;
}

#else /* !_WIN32 */

wdsniff *wdsniff_open(int priority, uint32_t range, sbuf *err, int *priv)
{
    (void)priority, (void)range;
    *priv = 0;
    sb_puts(err, "WinDivert is Windows only");
    return NULL;
}

void wdsniff_close(wdsniff *s) { (void)s; }

sock_t wdsniff_fd(const wdsniff *s)
{
    (void)s;
    return SOCK_INVALID;
}

int wdsniff_read(wdsniff *s, size_t max, wdsniff_cb cb, void *ctx, uint64_t *lost)
{
    (void)s, (void)max, (void)cb, (void)ctx, (void)lost;
    return -1;
}

#endif
