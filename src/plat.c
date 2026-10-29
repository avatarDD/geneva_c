#include "plat.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#  include <fcntl.h>
#  include <sys/time.h>
#endif

/* ---- time ---------------------------------------------------------------- */

#ifdef _WIN32

uint64_t plat_now_ms(void) { return (uint64_t)GetTickCount64(); }

uint64_t plat_wall_ms(void)
{
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    /* 100ns ticks since 1601 -> ms since 1970 */
    return (u.QuadPart - 116444736000000000ULL) / 10000ULL;
}

void plat_sleep_ms(unsigned ms) { Sleep(ms); }

#else

uint64_t plat_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

uint64_t plat_wall_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

void plat_sleep_ms(unsigned ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {
    }
}

#endif

/* ---- threads ------------------------------------------------------------- */

struct thread_start {
    plat_thread_fn fn;
    void *arg;
};

#ifdef _WIN32

static DWORD WINAPI thread_tramp(LPVOID p)
{
    struct thread_start s = *(struct thread_start *)p;
    free(p);
    s.fn(s.arg);
    return 0;
}

int plat_thread_start(plat_thread_t *t, plat_thread_fn fn, void *arg)
{
    struct thread_start *s = malloc(sizeof(*s));
    if (!s)
        return -1;
    s->fn = fn;
    s->arg = arg;
    *t = CreateThread(NULL, 0, thread_tramp, s, 0, NULL);
    if (!*t) {
        free(s);
        return -1;
    }
    return 0;
}

void plat_thread_join(plat_thread_t t)
{
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

void plat_mutex_init(plat_mutex_t *m) { InitializeCriticalSection(m); }
void plat_mutex_destroy(plat_mutex_t *m) { DeleteCriticalSection(m); }
void plat_mutex_lock(plat_mutex_t *m) { EnterCriticalSection(m); }
void plat_mutex_unlock(plat_mutex_t *m) { LeaveCriticalSection(m); }

#else

static void *thread_tramp(void *p)
{
    struct thread_start s = *(struct thread_start *)p;
    free(p);
    s.fn(s.arg);
    return NULL;
}

int plat_thread_start(plat_thread_t *t, plat_thread_fn fn, void *arg)
{
    pthread_attr_t attr;
    struct thread_start *s = malloc(sizeof(*s));
    int rc;
    if (!s)
        return -1;
    s->fn = fn;
    s->arg = arg;
    pthread_attr_init(&attr);
    /* Routers have little RAM: the default 8 MB stack reservation is waste. */
    pthread_attr_setstacksize(&attr, 256 * 1024);
    rc = pthread_create(t, &attr, thread_tramp, s);
    pthread_attr_destroy(&attr);
    if (rc != 0) {
        free(s);
        return -1;
    }
    return 0;
}

void plat_thread_join(plat_thread_t t) { pthread_join(t, NULL); }

void plat_mutex_init(plat_mutex_t *m) { pthread_mutex_init(m, NULL); }
void plat_mutex_destroy(plat_mutex_t *m) { pthread_mutex_destroy(m); }
void plat_mutex_lock(plat_mutex_t *m) { pthread_mutex_lock(m); }
void plat_mutex_unlock(plat_mutex_t *m) { pthread_mutex_unlock(m); }

#endif

/* ---- sockets ------------------------------------------------------------- */

#ifdef _WIN32

int plat_net_init(void)
{
    static int done;
    WSADATA wsa;
    if (done)
        return 0;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return -1;
    done = 1;
    return 0;
}

void plat_sock_close(sock_t s) { closesocket(s); }

int plat_sock_nonblock(sock_t s, int on)
{
    u_long mode = on ? 1 : 0;
    return ioctlsocket(s, FIONBIO, &mode) == 0 ? 0 : -1;
}

int plat_sock_err(void) { return WSAGetLastError(); }
int plat_sock_would_block(int err) { return err == WSAEWOULDBLOCK; }
int plat_sock_in_progress(int err) { return err == WSAEWOULDBLOCK || err == WSAEINPROGRESS; }

const char *plat_sock_strerror(int err)
{
    static _Thread_local char buf[160];
    DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
                             (DWORD)err, 0, buf, sizeof(buf), NULL);
    if (n == 0)
        snprintf(buf, sizeof(buf), "winsock error %d", err);
    else
        while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == '.'))
            buf[--n] = 0;
    return buf;
}

int plat_poll(plat_pollfd *fds, unsigned n, int timeout_ms)
{
    if (n == 0) {
        plat_sleep_ms(timeout_ms < 0 ? 1000 : (unsigned)timeout_ms);
        return 0;
    }
    return WSAPoll(fds, n, timeout_ms);
}

#else

int plat_net_init(void) { return 0; }
void plat_sock_close(sock_t s) { close(s); }

int plat_sock_nonblock(sock_t s, int on)
{
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0)
        return -1;
    fl = on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK);
    return fcntl(s, F_SETFL, fl);
}

int plat_sock_err(void) { return errno; }
int plat_sock_would_block(int err) { return err == EAGAIN || err == EWOULDBLOCK; }
int plat_sock_in_progress(int err) { return err == EINPROGRESS || err == EAGAIN; }
const char *plat_sock_strerror(int err) { return strerror(err); }

int plat_poll(plat_pollfd *fds, unsigned n, int timeout_ms)
{
    /* EINTR is returned to the caller on purpose: the main loops use it to
     * notice SIGINT/SIGTERM/SIGHUP promptly. */
    return poll(fds, n, timeout_ms);
}

#endif

/* ---- misc ---------------------------------------------------------------- */

void plat_random_bytes(void *buf, size_t len)
{
    unsigned char *p = buf;
    size_t got = 0;
#ifdef _WIN32
    /* RtlGenRandom lives in advapi32 as SystemFunction036. */
    typedef BOOLEAN(WINAPI * rtlgen_fn)(PVOID, ULONG);
    HMODULE h = LoadLibraryA("advapi32.dll");
    if (h) {
        rtlgen_fn fn = (rtlgen_fn)(void *)GetProcAddress(h, "SystemFunction036");
        if (fn && fn(buf, (ULONG)len))
            got = len;
        FreeLibrary(h);
    }
#else
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        got = fread(buf, 1, len, f);
        fclose(f);
    }
#endif
    if (got < len) {
        uint64_t x = plat_wall_ms() ^ ((uint64_t)plat_getpid() << 32) ^ (uint64_t)(uintptr_t)buf;
        for (size_t i = got; i < len; i++) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            p[i] = (unsigned char)x;
        }
    }
}

int plat_is_privileged(void)
{
#ifdef _WIN32
    BOOL admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
    PSID group;
    if (AllocateAndInitializeSid(&nt, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0,
                                 0, 0, 0, 0, &group)) {
        CheckTokenMembership(NULL, group, &admin);
        FreeSid(group);
    }
    return admin ? 1 : 0;
#else
    return geteuid() == 0;
#endif
}

int plat_getpid(void)
{
#ifdef _WIN32
    return (int)GetCurrentProcessId();
#else
    return (int)getpid();
#endif
}

const char *plat_os_name(void)
{
#if defined(_WIN32)
    return "windows";
#elif defined(__linux__)
    return "linux";
#elif defined(__FreeBSD__)
    return "freebsd";
#elif defined(__APPLE__)
    return "darwin";
#else
    return "unix";
#endif
}

const char *plat_arch_name(void)
{
#if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
    return "x86";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "aarch64";
#elif defined(__arm__)
#  if defined(__ARM_ARCH_7A__)
    return "armv7";
#  elif defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__)
    return "armv6";
#  else
    return "arm";
#  endif
#elif defined(__mips64)
#  if defined(__MIPSEL__)
    return "mips64el";
#  else
    return "mips64";
#  endif
#elif defined(__mips__)
#  if defined(__MIPSEL__)
    return "mipsel";
#  else
    return "mips";
#  endif
#elif defined(__riscv) && __riscv_xlen == 64
    return "riscv64";
#elif defined(__powerpc64__)
    return "ppc64";
#elif defined(__powerpc__)
    return "ppc";
#else
    return "unknown";
#endif
}
