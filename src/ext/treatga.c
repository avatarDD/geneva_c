/*
 * --ext-ga (treat.h): the genetic search of the treatment, "geneva evolve"
 * as a child process with its own queue and rules, one at a time. Linux:
 * the child is the binary itself (/proc/self/exe, read at the start); its
 * output is read by a thread of its own.
 */
#include "treat.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "library.h"
#include "log.h"
#include "plat.h"

#ifdef PLAT_LINUX
#  include <errno.h>
#  include <fcntl.h>
#  include <signal.h>
#  include <sys/prctl.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#define OUT_MAX 8192

static struct {
    int on;
    xga_config c;
    int running;      /* a child, its thread */
    volatile int done; /* the thread has its output */
#ifdef PLAT_LINUX
    pid_t pid;
    int fd;
    plat_thread_t th;
#endif
    char lib[256];    /* the seed file */
    char out[OUT_MAX];
    size_t outlen;
    int status;
} g;

int xga_set(const xga_config *c, sbuf *err)
{
    xga_stop();
    memset(&g, 0, sizeof(g));
    if (!c)
        return 0;
#ifndef PLAT_LINUX
    sb_puts(err, "--ext-ga is Linux-only");
    return -1;
#else
    g.c = *c;
    if (!g.c.exe[0]) {
        ssize_t n = readlink("/proc/self/exe", g.c.exe, sizeof(g.c.exe) - 1);
        if (n <= 0) {
            sb_printf(err, "--ext-ga: cannot find the binary itself: %s", strerror(errno));
            return -1;
        }
        g.c.exe[n] = 0;
    }
    g.on = 1;
    return 0;
#endif
}

int xga_on(void) { return g.on; }
int xga_running(void) { return g.running; }

#ifdef PLAT_LINUX
static void reader(void *arg)
{
    (void)arg;
    for (;;) {
        ssize_t n = g.outlen < OUT_MAX - 1 ? read(g.fd, g.out + g.outlen, OUT_MAX - 1 - g.outlen) : 0;
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            char sink[512];
            /* the rest (over OUT_MAX) is not needed, but must be read */
            while (g.outlen >= OUT_MAX - 1 && read(g.fd, sink, sizeof(sink)) > 0)
                ;
            break;
        }
        g.outlen += (size_t)n;
    }
    g.out[g.outlen] = 0;
    while (waitpid(g.pid, &g.status, 0) < 0 && errno == EINTR)
        ;
    atomic_store_int(&g.done, 1);
}

/* the seed: Geneva's client-side TCP strategies of the library (the lab's
 * too), one per line */
static int write_seed(sbuf *err)
{
    size_t n;
    const lib_entry *e = library_entries(&n);
    lib_filter f;
    FILE *fp;
    int fd;
    memset(&f, 0, sizeof(f));
    f.side = 1;
    f.with_lab = 1;
    if ((size_t)snprintf(g.lib, sizeof(g.lib), "%s/geneva-ga-XXXXXX", plat_tmpdir()) >= sizeof(g.lib)) {
        sb_puts(err, "the seed file: $TMPDIR is too long");
        g.lib[0] = 0;
        return -1;
    }
    if ((fd = mkstemp(g.lib)) < 0 || !(fp = fdopen(fd, "w"))) {
        sb_printf(err, "the seed file: %s", strerror(errno));
        if (fd >= 0)
            close(fd), unlink(g.lib);
        g.lib[0] = 0;
        return -1;
    }
    for (size_t i = 0; i < n; i++)
        if (library_match(&e[i], &f) && strstr(e[i].strategy, "TCP:") && strcmp(e[i].strategy, "\\/"))
            fprintf(fp, "%s\n", e[i].strategy);
    fclose(fp);
    return 0;
}
#endif

int xga_launch(const char *probe, const char *host, const char *ip, unsigned port, sbuf *err)
{
#ifndef PLAT_LINUX
    (void)probe, (void)host, (void)ip, (void)port;
    sb_puts(err, "--ext-ga is Linux-only");
    return -1;
#else
    char pop[16], gen[16], q[16], mark[16], prt[16];
    int pfd[2];
    pid_t parent;
    const char *argv[48];
    int k = 0;
    if (!g.on || g.running) {
        sb_puts(err, "a search runs already");
        return -1;
    }
    if (write_seed(err) < 0)
        return -1;
    snprintf(pop, sizeof(pop), "%d", g.c.pop);
    snprintf(gen, sizeof(gen), "%d", g.c.gen);
    snprintf(q, sizeof(q), "%u", g.c.queue);
    snprintf(mark, sizeof(mark), "0x%x", g.c.mark);
    snprintf(prt, sizeof(prt), "%u", port);
    argv[k++] = g.c.exe;
    argv[k++] = "evolve";
    argv[k++] = "--probe";
    argv[k++] = probe;
    argv[k++] = "--host";
    argv[k++] = host;
    argv[k++] = "--ip";
    argv[k++] = ip;
    argv[k++] = "--port";
    argv[k++] = prt;
    argv[k++] = "--timeout";
    argv[k++] = "2";
    argv[k++] = "--load-from";
    argv[k++] = g.lib;
    argv[k++] = "--population";
    argv[k++] = pop;
    argv[k++] = "--generations";
    argv[k++] = gen;
    argv[k++] = "--in-trees";
    argv[k++] = "1";
    argv[k++] = "--queue";
    argv[k++] = q;
    argv[k++] = "--mark";
    argv[k++] = mark;
    argv[k++] = "--firewall";
    argv[k++] = g.c.firewall[0] ? g.c.firewall : "auto";
    argv[k++] = "--top";
    argv[k++] = "1";
    argv[k++] = "--quiet";
    if (g.c.log[0]) {
        argv[k++] = "--log-file";
        argv[k++] = g.c.log;
    }
    if (g.c.rng_seed[0]) {
        argv[k++] = "--rng-seed";
        argv[k++] = g.c.rng_seed;
    }
    argv[k] = NULL;
    if (pipe(pfd) < 0) {
        sb_printf(err, "pipe: %s", strerror(errno));
        unlink(g.lib);
        return -1;
    }
    fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
    parent = getpid();
    g.pid = fork();
    if (g.pid < 0) {
        sb_printf(err, "fork: %s", strerror(errno));
        close(pfd[0]), close(pfd[1]);
        unlink(g.lib);
        return -1;
    }
    if (g.pid == 0) {
        int nul = open("/dev/null", O_RDWR);
        /* geneva run killed outright: the search still ends and takes its
         * rules down */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() != parent)
            _exit(127);
        dup2(pfd[1], 1);
        if (nul >= 0)
            dup2(nul, 0), dup2(nul, 2);
        /* the parent's descriptors (queue, sockets) stay out of the child */
        for (int fd = 3; fd < 1024; fd++)
            close(fd);
        execv(g.c.exe, (char *const *)argv);
        _exit(127);
    }
    close(pfd[1]);
    g.fd = pfd[0];
    g.outlen = 0;
    g.done = 0;
    if (plat_thread_start(&g.th, reader, NULL) < 0) {
        sb_puts(err, "cannot start the reader thread");
        kill(g.pid, SIGTERM);
        waitpid(g.pid, NULL, 0);
        close(g.fd);
        unlink(g.lib);
        return -1;
    }
    g.running = 1;
    LOGI("treat", "the genetic search runs (pid %d): %s --host %s --ip %s --port %u", (int)g.pid, probe, host, ip,
         port);
    return 0;
#endif
}

#ifdef PLAT_LINUX
static void reap(void)
{
    plat_thread_join(g.th);
    close(g.fd);
    if (g.lib[0])
        unlink(g.lib), g.lib[0] = 0;
    g.running = 0;
}
#endif

int xga_poll(char *out, size_t cap, double *fit)
{
#ifdef PLAT_LINUX
    char *line, *tab;
    if (!g.running || !atomic_load_int(&g.done))
        return 0;
    reap();
    *out = 0;
    *fit = 0;
    /* "fitness <TAB> generation <TAB> strategy": the best one first */
    line = g.out;
    tab = strchr(line, '\t');
    if (WIFEXITED(g.status) && WEXITSTATUS(g.status) == 0 && tab && strchr(tab + 1, '\t')) {
        char *s = strchr(tab + 1, '\t') + 1, *nl = strchr(s, '\n');
        if (nl)
            *nl = 0;
        *fit = strtod(line, NULL);
        snprintf(out, cap, "%s", s);
    } else {
        LOGW("treat", "the genetic search ended with status %d", g.status);
    }
    return 1;
#else
    (void)out, (void)cap, (void)fit;
    return 0;
#endif
}

void xga_stop(void)
{
#ifdef PLAT_LINUX
    if (!g.running)
        return;
    /* evolve takes its rules down on SIGTERM */
    kill(g.pid, SIGTERM);
    reap();
#endif
}
