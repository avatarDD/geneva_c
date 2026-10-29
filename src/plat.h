/*
 * Platform layer: everything that differs between POSIX (Linux, the BSDs,
 * routers on musl/uclibc) and Windows lives behind this header.
 */
#ifndef GENEVA_PLAT_H
#define GENEVA_PLAT_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef _WIN32_WINNT
#    define _WIN32_WINNT 0x0601
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <windows.h>
typedef SOCKET sock_t;
#  define SOCK_INVALID INVALID_SOCKET
#  define PLAT_WINDOWS 1
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <poll.h>
#  include <pthread.h>
#  include <unistd.h>
typedef int sock_t;
#  define SOCK_INVALID (-1)
#  define PLAT_POSIX 1
#endif

#if defined(__linux__)
#  define PLAT_LINUX 1
#endif

/* ---- time ---------------------------------------------------------------- */

/* Monotonic milliseconds, for timers and timeouts. */
uint64_t plat_now_ms(void);
/* Wall clock in milliseconds since the Unix epoch, for event timestamps. */
uint64_t plat_wall_ms(void);
void plat_sleep_ms(unsigned ms);

/* ---- threads ------------------------------------------------------------- */

#ifdef _WIN32
typedef HANDLE plat_thread_t;
typedef CRITICAL_SECTION plat_mutex_t;
#else
typedef pthread_t plat_thread_t;
typedef pthread_mutex_t plat_mutex_t;
#endif

typedef void (*plat_thread_fn)(void *arg);

int plat_thread_start(plat_thread_t *t, plat_thread_fn fn, void *arg);
void plat_thread_join(plat_thread_t t);
void plat_mutex_init(plat_mutex_t *m);
void plat_mutex_destroy(plat_mutex_t *m);
void plat_mutex_lock(plat_mutex_t *m);
void plat_mutex_unlock(plat_mutex_t *m);

/* Atomics over plain ints only: 64-bit atomics would need libatomic on
 * mips32/armv5, so counters stay thread-confined instead. */
#define atomic_load_int(p)      __atomic_load_n((p), __ATOMIC_SEQ_CST)
#define atomic_store_int(p, v)  __atomic_store_n((p), (v), __ATOMIC_SEQ_CST)

/* ---- sockets ------------------------------------------------------------- */

int plat_net_init(void);
void plat_sock_close(sock_t s);
int plat_sock_nonblock(sock_t s, int on);
/* Last socket error as a positive errno-like number. */
int plat_sock_err(void);
int plat_sock_would_block(int err);
int plat_sock_in_progress(int err);
const char *plat_sock_strerror(int err);
#ifdef _WIN32
typedef WSAPOLLFD plat_pollfd;
#else
typedef struct pollfd plat_pollfd;
#endif
int plat_poll(plat_pollfd *fds, unsigned n, int timeout_ms);

/* ---- files --------------------------------------------------------------- */

/* Writes a file so that a crash leaves either the old or the new contents:
 * PATH.tmp, flushed to disk, then renamed over PATH. Returns 0 or -1. */
int plat_write_atomic(const char *path, const void *data, size_t len);

/* ---- misc ---------------------------------------------------------------- */

/* Fill buf with OS randomness; falls back to time-derived bytes. */
void plat_random_bytes(void *buf, size_t len);
/* Returns non-zero when running with the privileges the engine needs. */
int plat_is_privileged(void);
int plat_getpid(void);
const char *plat_os_name(void);
const char *plat_arch_name(void);

#endif
