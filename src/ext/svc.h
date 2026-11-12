/*
 * geneva run --ext as a service (docs/EXT_ROADMAP.md, N1, N2, N4, N5):
 * zapret2's --daemon, --pidfile, --user/--uid with capabilities, seccomp
 * (sec_harden), systemd's sd_notify and syslog.
 *
 * Privileges go once packets flow (the engine's on_ready): the NFQUEUE and
 * raw sockets are open and the rules are up. The process then keeps only
 * CAP_NET_ADMIN and CAP_NET_RAW (--user/--uid) and forbids exec, kill,
 * ptrace and changes of the file system (seccomp, like zapret2). The rules
 * still come down on every exit: a helper forked before, that stays root
 * and unfiltered, waits on a pipe and takes them down (and removes the
 * pidfile) when the engine asks or when the pipe closes, even after a
 * SIGKILL of the engine.
 */
#ifndef GENEVA_EXT_SVC_H
#define GENEVA_EXT_SVC_H

#include <stddef.h>
#include <stdint.h>

#include "args.h"
#include "fw.h"
#include "util.h"

#define XSVC_MAX_GIDS 64

typedef struct {
    const char *pidfile;
    int daemon;
    int drop;      /* --user or --uid */
    const char *user;
    uint32_t uid, gid[XSVC_MAX_GIDS];
    int ngid;
    int seccomp;   /* --ext-seccomp (1 on Linux) */
    int syslog;    /* --log-target syslog */
    int dry_run;
    /* filled at the start */
    int ready_fd;  /* --daemon: the parent waits on it */
    int fail;      /* exit code when hardening failed, 0 */
} xsvc;

/* Reads the options (with --ext). Returns 0, or -1 with a message in err. */
int xsvc_parse(const args_t *a, xsvc *s, sbuf *err);

/* --ext-workers N|auto (1..64; auto: ncpu, at most 4): the worker threads
 * of the engine, each with its own NFQUEUE (queue .. queue+N-1). windows:
 * refused there for now. Returns 0 with *out (1 without the option), or -1
 * with a message in err. */
#define XSVC_MAX_WORKERS 64
#define XSVC_AUTO_WORKERS 4
int xsvc_workers(const args_t *a, uint16_t queue, int windows, unsigned ncpu, unsigned *out, sbuf *err);

/* Before the engine starts: --daemon (the parent waits for the child to be
 * ready and returns its exit code: >= 0; the child goes on: -1), then the
 * pidfile and syslog. Returns -1 to go on, or an exit code. */
int xsvc_start(xsvc *s, sbuf *err);

/* Packets flow (engine on_ready): the helper, then --user/--uid and
 * seccomp, then READY=1 to the daemon's parent and to systemd. fw: the
 * rules to take down at the end (NULL: none). Returns 0, or an exit code
 * when the engine should stop. */
int xsvc_ready(xsvc *s, const fw_config *fw);

/* After the engine: STOPPING=1, the pidfile, the helper. */
void xsvc_stop(xsvc *s);

/* The parts, for tests */
int xsvc_parse_uid(const char *s, xsvc *v);
/* sd_notify(3) without libsystemd: sends msg to $NOTIFY_SOCKET (nothing when
 * it is not set). Returns 0, or -1 when sending failed. */
int xsvc_notify(const char *msg);
/* The seccomp program of the running architecture: count of 8-byte
 * instructions written to out (max of them), 0 when this architecture is
 * not known. */
size_t xsec_program(uint8_t *out, size_t max);
/* PR_SET_NO_NEW_PRIVS and the filter. Returns 0 or -1 (errno). */
int xsec_apply(void);
/* One syslog line: "<PRI>geneva[PID]: mod: msg" */
void xsvc_syslog_format(sbuf *out, int level, const char *mod, const char *msg, long pid);

#endif
