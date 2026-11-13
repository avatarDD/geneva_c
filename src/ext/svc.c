#include "svc.h"
#include "sec_win.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "log.h"
#include "plat.h"

#ifdef PLAT_POSIX
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/un.h>
#  include <sys/wait.h>
#endif
#ifdef PLAT_LINUX
#  include <grp.h>
#  include <pwd.h>
#  include <sys/prctl.h>
#  include <sys/syscall.h>
#endif

/* ---- options ------------------------------------------------------------- */

int xsvc_parse_uid(const char *s, xsvc *v)
{
    char *end;
    unsigned long n = strtoul(s, &end, 10);
    if (end == s || n > 0xfffffffeUL)
        return -1;
    v->uid = (uint32_t)n;
    v->ngid = 0;
    if (!*end) {
        v->gid[v->ngid++] = (uint32_t)n; /* zapret2: the gid is the uid */
        return 0;
    }
    if (*end != ':')
        return -1;
    do {
        s = end + 1;
        n = strtoul(s, &end, 10);
        if (end == s || n > 0xfffffffeUL || v->ngid >= XSVC_MAX_GIDS)
            return -1;
        v->gid[v->ngid++] = (uint32_t)n;
    } while (*end == ',');
    return *end ? -1 : 0;
}

int xsvc_parse(const args_t *a, xsvc *s, sbuf *err)
{
    const char *v;
    memset(s, 0, sizeof(*s));
    s->ready_fd = -1;
    s->dry_run = arg_has(a, "dry-run");
    s->daemon = arg_has(a, "daemon");
    s->pidfile = arg_str(a, "pidfile", NULL);
    if (s->pidfile && !*s->pidfile) {
        sb_puts(err, "--pidfile needs a file");
        return -1;
    }
    if ((v = arg_str(a, "log-target", NULL)) != NULL) {
        if (strcmp(v, "syslog")) {
            sb_puts(err, "--log-target must be syslog");
            return -1;
        }
        s->syslog = 1;
    }
    if (arg_has(a, "user") && arg_has(a, "uid")) {
        sb_puts(err, "--user and --uid exclude each other");
        return -1;
    }
#ifdef PLAT_LINUX
    s->seccomp = 1;
#endif
    if (arg_has(a, "ext-seccomp")) {
        v = arg_str(a, "ext-seccomp", "");
        if (*v && strcmp(v, "0") && strcmp(v, "1")) {
            sb_puts(err, "--ext-seccomp must be 0 or 1");
            return -1;
        }
        s->seccomp = strcmp(v, "0") != 0;
    }
    if (xsbx_parse(a, &s->sandbox, err) < 0)
        return -1;
#ifndef PLAT_LINUX
    if (s->seccomp || arg_has(a, "user") || arg_has(a, "uid") || s->daemon) {
        sb_puts(err, "--daemon, --user, --uid and --ext-seccomp are Linux-only");
        return -1;
    }
#  ifndef PLAT_POSIX
    if (s->syslog) {
        sb_puts(err, "--log-target syslog is not on Windows");
        return -1;
    }
#  endif
#else
    if ((v = arg_str(a, "uid", NULL)) != NULL) {
        if (xsvc_parse_uid(v, s) < 0) {
            sb_puts(err, "bad --uid (UID or UID:GID,GID,...)");
            return -1;
        }
        s->drop = 1;
    }
    if ((v = arg_str(a, "user", NULL)) != NULL) {
        struct passwd *pw = getpwnam(v);
        if (!pw) {
            sb_printf(err, "no user %s", v);
            return -1;
        }
        s->user = v;
        s->uid = pw->pw_uid;
        s->gid[0] = pw->pw_gid;
        s->ngid = 1;
        s->drop = 1;
    }
    if (s->drop && geteuid()) {
        /* nothing to drop; zapret2 refuses as well */
        if (!s->dry_run) {
            sb_puts(err, "--user/--uid need root");
            return -1;
        }
    }
#endif
    return 0;
}

/* ---- syslog -------------------------------------------------------------- */

void xsvc_syslog_format(sbuf *out, int level, const char *mod, const char *msg, long pid)
{
    /* LOG_DAEMON; error, warning, info, debug */
    static const int sev[] = {3, 4, 6, 7, 7};
    sb_printf(out, "<%d>geneva[%ld]: %s: %s", 3 * 8 + sev[level >= 0 && level < 5 ? level : 4], pid, mod, msg);
}

#ifdef PLAT_POSIX
static int g_slog = -1, g_slog_stream;

static int slog_connect(void)
{
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strcpy(a.sun_path, "/dev/log");
    for (int stream = 0; stream < 2; stream++) {
        int fd = socket(AF_UNIX, (stream ? SOCK_STREAM : SOCK_DGRAM), 0);
        if (fd < 0)
            return -1;
        if (connect(fd, (struct sockaddr *)&a, sizeof(a)) == 0) {
            fcntl(fd, F_SETFD, FD_CLOEXEC);
            g_slog = fd;
            g_slog_stream = stream;
            return 0;
        }
        close(fd);
        if (errno != EPROTOTYPE)
            return -1;
    }
    return -1;
}

static void slog_hook(log_level lvl, const char *mod, const char *msg)
{
    sbuf l;
    sb_init(&l);
    xsvc_syslog_format(&l, (int)lvl, mod, msg, (long)getpid());
    if (g_slog_stream)
        sb_putc(&l, 0);
    for (int tries = 0; tries < 2; tries++) {
        if (g_slog < 0 && slog_connect() < 0)
            break;
        if (send(g_slog, l.data, l.len, MSG_NOSIGNAL) >= 0)
            break;
        close(g_slog); /* syslogd restarted: once more */
        g_slog = -1;
    }
    sb_free(&l);
}

int xsvc_notify(const char *msg)
{
    const char *path = getenv("NOTIFY_SOCKET");
    struct sockaddr_un a;
    size_t n;
    int fd, r;
    if (!path || !*path)
        return 0;
    n = strlen(path);
    if ((path[0] != '/' && path[0] != '@') || n >= sizeof(a.sun_path))
        return -1;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    memcpy(a.sun_path, path, n);
    if (path[0] == '@')
        a.sun_path[0] = 0; /* abstract */
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    r = (int)sendto(fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&a,
                    (socklen_t)(offsetof(struct sockaddr_un, sun_path) + n));
    close(fd);
    return r < 0 ? -1 : 0;
}
#else
int xsvc_notify(const char *msg)
{
    (void)msg;
    return 0;
}
#endif

/* ---- seccomp (zapret2's sec_harden) --------------------------------------- */

#ifdef PLAT_LINUX
#  if defined(__x86_64__)
#    define XSEC_ARCH 0xC000003Eu
#    define XSEC_X32 1
#  elif defined(__i386__)
#    define XSEC_ARCH 0x40000003u
#  elif defined(__aarch64__)
#    define XSEC_ARCH (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ? 0x800000B7u : 0xC00000B7u)
#  elif defined(__arm__)
#    define XSEC_ARCH (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ? 0x00000028u : 0x40000028u)
#  elif defined(__mips__)
#    if defined(_ABIO32)
#      define XSEC_MIPS 0x00000008u
#    elif defined(_ABIN32)
#      define XSEC_MIPS 0x20000008u
#    else
#      define XSEC_MIPS 0x80000008u
#    endif
#    define XSEC_ARCH (XSEC_MIPS | (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ? 0 : 0x40000000u))
#  elif defined(__powerpc64__)
#    define XSEC_ARCH (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__ ? 0x80000015u : 0xC0000015u)
#  elif defined(__powerpc__)
#    define XSEC_ARCH 0x00000014u
#  elif defined(__riscv) && __riscv_xlen == 64
#    define XSEC_ARCH 0xC00000F3u
#  elif defined(__loongarch64)
#    define XSEC_ARCH 0xC0000102u
#  elif defined(__s390x__)
#    define XSEC_ARCH 0x80000016u
#  endif

/* the syscalls zapret2 blocks */
static const long blocked[] = {
#  ifdef SYS_execv
    SYS_execv,
#  endif
    SYS_execve,
#  ifdef SYS_execveat
    SYS_execveat,
#  endif
#  ifdef SYS_chmod
    SYS_chmod,
#  endif
    SYS_fchmod, SYS_fchmodat,
#  ifdef SYS_chown
    SYS_chown,
#  endif
#  ifdef SYS_chown32
    SYS_chown32,
#  endif
    SYS_fchown,
#  ifdef SYS_fchown32
    SYS_fchown32,
#  endif
#  ifdef SYS_lchown
    SYS_lchown,
#  endif
#  ifdef SYS_lchown32
    SYS_lchown32,
#  endif
    SYS_fchownat,
#  ifdef SYS_symlink
    SYS_symlink,
#  endif
    SYS_symlinkat,
#  ifdef SYS_link
    SYS_link,
#  endif
    SYS_linkat,
#  ifdef SYS_mknod
    SYS_mknod,
#  endif
    SYS_mknodat,
#  ifdef SYS_mkdir
    SYS_mkdir,
#  endif
    SYS_mkdirat,
#  ifdef SYS_rmdir
    SYS_rmdir,
#  endif
#  ifdef SYS_getdents
    SYS_getdents,
#  endif
#  ifdef SYS_getdents64
    SYS_getdents64,
#  endif
#  ifdef SYS_process_vm_readv
    SYS_process_vm_readv,
#  endif
#  ifdef SYS_process_vm_writev
    SYS_process_vm_writev,
#  endif
#  ifdef SYS_process_madvise
    SYS_process_madvise,
#  endif
#  ifdef SYS_tkill
    SYS_tkill,
#  endif
#  ifdef SYS_tgkill
    SYS_tgkill,
#  endif
    SYS_kill, SYS_ptrace,
};
#  define NBLOCKED (sizeof(blocked) / sizeof(*blocked))
#endif

/* classic BPF: code (16), jt, jf, k (32), in host order as the kernel
 * reads struct sock_filter */
static void insn(uint8_t *o, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k)
{
    memcpy(o, &code, 2);
    o[2] = jt;
    o[3] = jf;
    memcpy(o + 4, &k, 4);
}

size_t xsec_program(uint8_t *out, size_t max)
{
#if defined(PLAT_LINUX) && defined(XSEC_ARCH)
    enum { LD = 0x20, JEQ = 0x15, JGE = 0x35, RET = 0x06 };
    const uint32_t allow = 0x7fff0000u, kill = 0x80000000u; /* SECCOMP_RET_KILL_PROCESS */
#  ifdef XSEC_X32
    const size_t pre = 4;
#  else
    const size_t pre = 3;
#  endif
    size_t n = pre + NBLOCKED + 2, i = 0;
    if (n > max)
        return 0;
    /* the architecture (seccomp_data.arch at 4): another one is killed */
    insn(out + 8 * i++, LD, 0, 0, 4);
    insn(out + 8 * i, JEQ, 0, (uint8_t)(n - 2 - i), XSEC_ARCH);
    i++;
    insn(out + 8 * i++, LD, 0, 0, 0); /* seccomp_data.nr */
#  ifdef XSEC_X32
    insn(out + 8 * i, JGE, (uint8_t)(n - 2 - i), 0, 0x40000000u); /* x32 calls */
    i++;
#  endif
    for (size_t b = 0; b < NBLOCKED; b++, i++)
        insn(out + 8 * i, JEQ, (uint8_t)(n - 2 - i), 0, (uint32_t)blocked[b]);
    insn(out + 8 * i++, RET, 0, 0, allow);
    insn(out + 8 * i++, RET, 0, 0, kill);
    return i;
#else
    (void)out, (void)max, (void)insn;
    return 0;
#endif
}

int xsec_apply(void)
{
#ifdef PLAT_LINUX
    uint8_t prog[8 * 64];
    struct {
        unsigned short len;
        void *filter;
    } fp;
    size_t n = xsec_program(prog, sizeof(prog) / 8);
    if (!n) {
        errno = ENOSYS;
        return -1;
    }
    if (prctl(38 /* PR_SET_NO_NEW_PRIVS */, 1, 0, 0, 0) < 0)
        return -1;
    fp.len = (unsigned short)n;
    fp.filter = prog;
    return prctl(22 /* PR_SET_SECCOMP */, 2 /* SECCOMP_MODE_FILTER */, &fp, 0, 0) < 0 ? -1 : 0;
#else
    errno = ENOSYS;
    return -1;
#endif
}

/* ---- root ------------------------------------------------------------------ */

#ifdef PLAT_LINUX
/* struct __user_cap_header_struct, __user_cap_data_struct (version 3) */
typedef struct {
    uint32_t version;
    int pid;
} cap_hdr;
typedef struct {
    uint32_t effective, permitted, inheritable;
} cap_data;

enum { CAP_SETPCAP_ = 8, CAP_NET_ADMIN_ = 12, CAP_NET_RAW_ = 13 };

static int setcaps(uint64_t caps)
{
    cap_hdr h = {0x20080522u, 0};
    cap_data d[2];
    memset(d, 0, sizeof(d));
    d[0].effective = d[0].permitted = (uint32_t)caps;
    d[1].effective = d[1].permitted = (uint32_t)(caps >> 32);
    return (int)syscall(SYS_capset, &h, d);
}

static int last_cap(void)
{
    int n = 40;
    FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
    if (f) {
        if (fscanf(f, "%d", &n) != 1 || n < 0 || n > 63)
            n = 40;
        fclose(f);
    }
    return n;
}

/* zapret2's droproot and dropcaps */
static int drop_root(const xsvc *s, sbuf *err)
{
    const uint64_t keep = (1ULL << CAP_NET_ADMIN_) | (1ULL << CAP_NET_RAW_);
    int maxcap = last_cap();
    gid_t g[XSVC_MAX_GIDS];
    for (int i = 0; i < s->ngid; i++)
        g[i] = (gid_t)s->gid[i];
    if (s->user ? initgroups(s->user, g[0]) : setgroups((size_t)s->ngid, g)) {
        sb_printf(err, "setgroups: %s", strerror(errno));
        return -1;
    }
    if (setgid(g[0])) {
        sb_printf(err, "setgid: %s", strerror(errno));
        return -1;
    }
    if (prctl(8 /* PR_SET_KEEPCAPS */, 1, 0, 0, 0) < 0 || setuid((uid_t)s->uid)) {
        sb_printf(err, "setuid: %s", strerror(errno));
        return -1;
    }
    prctl(8, 0, 0, 0, 0);
    if (setcaps(keep | (1ULL << CAP_SETPCAP_)) == 0)
        for (int c = 0; c <= maxcap; c++)
            if (c != CAP_NET_ADMIN_ && c != CAP_NET_RAW_)
                prctl(24 /* PR_CAPBSET_DROP */, c, 0, 0, 0);
    if (setcaps(keep)) {
        sb_printf(err, "capset: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ---- the root helper --------------------------------------------------------- */

static pid_t g_helper;
static int g_helper_used; /* it ran: the pidfile is its */
static int g_helper_fd = -1;  /* to it: a byte, or the end */
static int g_helper_ack = -1; /* from it: done */
static fw_config g_fw;
static int g_fw_on;
static const char *g_pidfile;

static void helper(int in, int out)
{
    char c;
    ssize_t r;
    signal(SIGINT, SIG_IGN); /* ^C reaches the whole process group */
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    fw_set_down_hook(NULL);
    do
        r = read(in, &c, 1);
    while (r < 0 && errno == EINTR);
    if (g_fw_on) {
        if (r <= 0)
            LOGW("svc", "the engine is gone: taking the firewall rules down");
        fw_down(&g_fw);
    }
    if (g_pidfile)
        unlink(g_pidfile);
    if (write(out, "1", 1) < 0) {
        /* the engine does not wait */
    }
    _exit(0);
}

static void helper_done(void)
{
    char c;
    if (g_helper <= 0)
        return;
    if (write(g_helper_fd, "d", 1) < 0) {
        /* it is gone; wait below */
    }
    close(g_helper_fd);
    while (read(g_helper_ack, &c, 1) < 0 && errno == EINTR)
        ;
    close(g_helper_ack);
    while (waitpid(g_helper, NULL, 0) < 0 && errno == EINTR)
        ;
    g_helper = 0;
    g_helper_fd = g_helper_ack = -1;
    g_fw_on = 0;
    g_pidfile = NULL;
    fw_set_down_hook(NULL);
}

static void down_hook(const fw_config *c)
{
    (void)c;
    helper_done();
}

static int helper_start(const fw_config *fw, const char *pidfile, sbuf *err)
{
    int to[2], from[2];
    if (pipe(to) < 0) {
        sb_printf(err, "pipe: %s", strerror(errno));
        return -1;
    }
    if (pipe(from) < 0) {
        sb_printf(err, "pipe: %s", strerror(errno));
        close(to[0]);
        close(to[1]);
        return -1;
    }
    if (fw) {
        g_fw = *fw;
        g_fw_on = 1;
    }
    g_pidfile = pidfile;
    fflush(NULL);
    g_helper = fork();
    if (g_helper < 0) {
        sb_printf(err, "fork: %s", strerror(errno));
        g_helper = 0;
        g_fw_on = 0;
        g_pidfile = NULL;
        close(to[0]);
        close(to[1]);
        close(from[0]);
        close(from[1]);
        return -1;
    }
    if (!g_helper) {
        close(to[1]);
        close(from[0]);
        helper(to[0], from[1]);
    }
    close(to[0]);
    close(from[1]);
    fcntl(to[1], F_SETFD, FD_CLOEXEC);
    fcntl(from[0], F_SETFD, FD_CLOEXEC);
    g_helper_fd = to[1];
    g_helper_ack = from[0];
    g_helper_used = 1;
    fw_set_down_hook(down_hook);
    return 0;
}
#endif

/* ---- start, ready, stop ------------------------------------------------------- */

static int write_pidfile(const char *path, sbuf *err)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        sb_printf(err, "cannot write %s: %s", path, strerror(errno));
        return -1;
    }
#ifdef PLAT_POSIX
    fprintf(f, "%ld\n", (long)getpid());
#else
    fprintf(f, "%lu\n", (unsigned long)GetCurrentProcessId());
#endif
    if (fclose(f)) {
        sb_printf(err, "cannot write %s", path);
        return -1;
    }
    return 0;
}

int xsvc_start(xsvc *s, sbuf *err)
{
#ifdef PLAT_LINUX
    if (s->daemon) {
        int p[2];
        pid_t pid;
        char c;
        ssize_t r;
        fflush(NULL);
        if (pipe(p) < 0) {
            sb_printf(err, "pipe: %s", strerror(errno));
            return EXIT_FAIL;
        }
        pid = fork();
        if (pid < 0) {
            sb_printf(err, "fork: %s", strerror(errno));
            return EXIT_FAIL;
        }
        if (pid) {
            int st;
            close(p[1]);
            do
                r = read(p[0], &c, 1);
            while (r < 0 && errno == EINTR);
            if (r == 1)
                return EXIT_OK; /* running */
            while (waitpid(pid, &st, 0) < 0 && errno == EINTR)
                ;
            return WIFEXITED(st) && WEXITSTATUS(st) ? WEXITSTATUS(st) : EXIT_FAIL;
        }
        close(p[0]);
        fcntl(p[1], F_SETFD, FD_CLOEXEC);
        s->ready_fd = p[1];
        setsid();
        {
            /* stderr goes once running: start errors still reach the
             * terminal of the parent */
            int fd = open("/dev/null", O_RDWR);
            if (fd >= 0) {
                dup2(fd, 0);
                dup2(fd, 1);
                if (fd > 2)
                    close(fd);
            }
        }
    }
#endif
    if (s->pidfile && write_pidfile(s->pidfile, err) < 0)
        return EXIT_IO;
    xsbx_file(s->pidfile); /* removed on exit */
#ifdef PLAT_POSIX
    if (s->syslog) {
        if (slog_connect() < 0)
            LOGW("svc", "no syslog at /dev/log yet: %s", strerror(errno));
        log_set_hook(slog_hook);
    }
#endif
    return -1;
}

int xsvc_ready(xsvc *s, const fw_config *fw)
{
#ifdef PLAT_LINUX
    sbuf err;
    sb_init(&err);
    if ((s->drop || s->seccomp) && (fw || s->pidfile) && helper_start(fw, s->pidfile, &err) < 0) {
        LOGE("svc", "%s", err.data);
        sb_free(&err);
        s->fail = EXIT_FAIL;
        return s->fail;
    }
    if (s->drop) {
        if (drop_root(s, &err) < 0) {
            LOGE("svc", "dropping root: %s", err.data);
            sb_free(&err);
            s->fail = EXIT_PRIV;
            return s->fail;
        }
        LOGI("svc", "running as uid %u gid %u with CAP_NET_ADMIN and CAP_NET_RAW", (unsigned)getuid(),
             (unsigned)getgid());
    }
    sb_free(&err);
    if (s->seccomp) {
        if (xsec_apply() < 0)
            LOGW("svc", "seccomp: %s%s", strerror(errno),
                 errno == EINVAL || errno == ENOSYS ? " (the kernel or this architecture has none: running without)"
                                                    : "");
        else
            LOGD("svc", "seccomp filter on");
    }
    if (s->ready_fd >= 0) {
        int fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
            dup2(fd, 2);
            if (fd > 2)
                close(fd);
        }
        if (write(s->ready_fd, "1", 1) < 0) {
            /* the parent is gone */
        }
        close(s->ready_fd);
        s->ready_fd = -1;
    }
#else
    (void)fw;
    if (s->sandbox) {
        sbuf err;
        sb_init(&err);
        if (xsbx_apply(&err) < 0) {
            LOGE("svc", "%s (--ext-sandbox 0 runs without it)", err.data);
            sb_free(&err);
            s->fail = EXIT_PRIV;
            return s->fail;
        }
        sb_free(&err);
    }
#endif
    if (xsvc_notify("READY=1") < 0)
        LOGW("svc", "sd_notify: %s", strerror(errno));
    return 0;
}

void xsvc_stop(xsvc *s)
{
    xsvc_notify("STOPPING=1");
    int helper = 0;
#ifdef PLAT_LINUX
    helper = g_helper > 0 || g_helper_used;
    helper_done(); /* the rules, if still up, and the pidfile */
#endif
    if (s->pidfile && !helper)
        remove(s->pidfile);
#ifdef PLAT_POSIX
    if (s->syslog) {
        log_set_hook(NULL);
        if (g_slog >= 0)
            close(g_slog);
        g_slog = -1;
    }
#endif
}

int xsvc_workers(const args_t *a, uint16_t queue, int windows, unsigned ncpu, unsigned *out, sbuf *err)
{
    const char *s = arg_str(a, "ext-workers", NULL);
    unsigned n;
    *out = 1;
    if (!s)
        return 0;
    if (!strcmp(s, "auto")) {
        n = ncpu ? ncpu : 1;
        if (n > XSVC_AUTO_WORKERS)
            n = XSVC_AUTO_WORKERS;
    } else {
        char *end;
        unsigned long v;
        errno = 0;
        v = strtoul(s, &end, 10);
        if (errno || end == s || *end || *s == '-' || *s == '+' || v < 1 || v > XSVC_MAX_WORKERS) {
            sb_printf(err, "bad --ext-workers %s (1..%d or auto)", s, XSVC_MAX_WORKERS);
            return -1;
        }
        n = (unsigned)v;
    }
    if (n > 1 && windows) {
        sb_puts(err, "--ext-workers: Linux only for now");
        return -1;
    }
    if ((unsigned)queue + n - 1 > 65535) {
        sb_printf(err, "--ext-workers %u: the queues %u..%u go past 65535", n, queue, (unsigned)queue + n - 1);
        return -1;
    }
    *out = n;
    return 0;
}
