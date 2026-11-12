/* Stage X7a: options from a file (src/ext/cfgfile.c) and running as a
 * service (src/ext/svc.c): --uid, syslog lines, sd_notify, seccomp. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "plat.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/cfgfile.h"
#  include "ext/svc.h"

#  ifdef PLAT_LINUX
#    include <fcntl.h>
#    include <signal.h>
#    include <sys/stat.h>
#    include <sys/un.h>
#    include <sys/wait.h>
#  endif

#  ifdef _WIN32
#    define setenv(n, v, o) _putenv_s(n, v)
#    define unsetenv(n) _putenv_s(n, "")
#  endif

/* the words of text joined by '|', or "ERR: message" */
static char *split(const char *text)
{
    char **w;
    sbuf err, out;
    int n;
    sb_init(&err);
    sb_init(&out);
    n = xcfg_split(text, strlen(text), &w, &err);
    if (n < 0) {
        sb_printf(&out, "ERR: %s", err.data);
    } else {
        for (int i = 0; i < n; i++)
            sb_printf(&out, "%s%s", i ? "|" : "", w[i]);
        CHECK(w[n] == NULL);
        xcfg_free(w);
    }
    sb_free(&err);
    if (!out.data)
        sb_puts(&out, "");
    return sb_take(&out);
}

#  define SPLIT(text, want)                                                                              \
        do {                                                                                             \
            char *_s = split(text);                                                                      \
            CHECK_STR(_s, want);                                                                         \
            free(_s);                                                                                    \
        } while (0)

TEST(svc_split)
{
    SPLIT("", "");
    SPLIT("  \n\t ", "");
    SPLIT("--ext -s x", "--ext|-s|x");
    SPLIT("a\r\nb", "a|b");
    SPLIT("'a b' \"c d\"", "a b|c d");
    SPLIT("x'a b'y", "xa by");
    SPLIT("''", "");
    SPLIT("a\\ b", "a b");
    SPLIT("\"a\\\"b\\\\c\\$d\\x\"", "a\"b\\c$d\\x");
    SPLIT("'\\n$X'", "\\n$X");
    SPLIT("# all of this\n--ext # this too\nb#c", "--ext|b#c");
    SPLIT("-s '[TCP:flags:PA]-drop-| \\/'", "-s|[TCP:flags:PA]-drop-| \\/");
    SPLIT("a\\\nb", "ab");
    SPLIT("$ a$", "$|a$");
    setenv("GENEVA_T_V", "v 1", 1);
    unsetenv("GENEVA_T_NONE");
    SPLIT("$GENEVA_T_V", "v 1");
    SPLIT("p${GENEVA_T_V}q", "pv 1q");
    SPLIT("\"[$GENEVA_T_V]\"", "[v 1]");
    SPLIT("x$GENEVA_T_NONE", "x");
    SPLIT("'unterminated", "ERR: unterminated '");
    SPLIT("\"unterminated", "ERR: unterminated \"");
    SPLIT("a\\", "ERR: a backslash at the end");
    SPLIT("$(id)", "ERR: $( ) runs a command: not allowed");
    SPLIT("`id`", "ERR: `...` runs a command: not allowed");
    SPLIT("\"`id`\"", "ERR: `...` runs a command: not allowed");
    SPLIT("${A", "ERR: bad ${NAME}");
    SPLIT("${}", "ERR: bad ${NAME}");
    {
        char t[4] = {'a', 0, 'b', 0};
        char **w;
        sbuf err;
        sb_init(&err);
        CHECK_INT(xcfg_split(t, 3, &w, &err), -1);
        CHECK_STR(err.data, "a NUL byte");
        sb_free(&err);
    }
}

TEST(svc_expand)
{
    const char *path = "geneva-test-cfg.txt";
    char a0[64], *argv0[4], **argv;
    int argc;
    sbuf err;
    sb_init(&err);
    /* no file: nothing changes */
    argv0[0] = (char *)"--ext";
    argv0[1] = NULL;
    argv = argv0;
    argc = 1;
    CHECK_INT(xcfg_expand(&argc, &argv, &err), 0);
    CHECK(argv == argv0);
    argc = 0;
    CHECK_INT(xcfg_expand(&argc, &argv, &err), 0);

    CHECK_INT(write_file(path, "--ext\n-s 'a b'\n", 15), 0);
    snprintf(a0, sizeof(a0), "@%s", path);
    argv0[0] = a0;
    argv0[1] = (char *)"-v";
    argv0[2] = NULL;
    argv = argv0;
    argc = 2;
    CHECK_INT(xcfg_expand(&argc, &argv, &err), 1);
    CHECK_INT(argc, 4);
    CHECK_STR(argv[0], "--ext");
    CHECK_STR(argv[2], "a b");
    CHECK_STR(argv[3], "-v");
    CHECK(argv[4] == NULL);
    for (int i = 0; i < 3; i++)
        free(argv[i]);
    free(argv);

    /* $FILE as well */
    snprintf(a0, sizeof(a0), "$%s", path);
    argv = argv0;
    argc = 1;
    CHECK_INT(xcfg_expand(&argc, &argv, &err), 1);
    CHECK_INT(argc, 3);
    for (int i = 0; i < 3; i++)
        free(argv[i]);
    free(argv);

    /* without --ext */
    CHECK_INT(write_file(path, "-s x", 4), 0);
    snprintf(a0, sizeof(a0), "@%s", path);
    argv = argv0;
    argc = 1;
    CHECK_INT(xcfg_expand(&argc, &argv, &err), -1);
    CHECK(strstr(err.data, "need --ext") != NULL);
    /* ... unless it comes after the file */
    argv0[1] = (char *)"--ext";
    argc = 2;
    CHECK_INT(xcfg_expand(&argc, &argv, &err), 1);
    CHECK_INT(argc, 3);
    for (int i = 0; i < 2; i++)
        free(argv[i]);
    free(argv);

    /* a bad file */
    CHECK_INT(write_file(path, "--ext 'x", 8), 0);
    argv = argv0;
    argc = 1;
    sb_reset(&err);
    CHECK_INT(xcfg_expand(&argc, &argv, &err), -1);
    CHECK(strstr(err.data, "unterminated") != NULL);
    remove(path);
    sb_reset(&err);
    CHECK_INT(xcfg_expand(&argc, &argv, &err), -1);
    CHECK(strstr(err.data, "cannot read") != NULL);
    argv0[0] = (char *)"@";
    CHECK_INT(xcfg_expand(&argc, &argv, &err), -1);
    sb_free(&err);
}

static int parse_run(xsvc *s, const char *o1, const char *v1, const char *o2, sbuf *err)
{
    static const optdef defs[] = {EXT_OPT, EXT_RUN_OPTS, {NULL, 0, 0, NULL, NULL}};
    const char *argv[6] = {"--ext"};
    int argc = 1, r;
    args_t a;
    char e[128];
    if (o1)
        argv[argc++] = o1;
    if (v1)
        argv[argc++] = v1;
    if (o2)
        argv[argc++] = o2;
    if (args_parse(&a, argc, (char **)argv, defs, e, sizeof(e)) < 0) {
        sb_puts(err, e);
        return -2;
    }
    r = xsvc_parse(&a, s, err);
    args_free(&a);
    return r;
}

static int workers(const char *v, uint16_t queue, int windows, unsigned ncpu, unsigned *out, sbuf *err)
{
    static const optdef defs[] = {EXT_OPT, EXT_RUN_OPTS, {NULL, 0, 0, NULL, NULL}};
    const char *argv[] = {"--ext", "--ext-workers", v, NULL};
    args_t a;
    char e[128];
    int r;
    if (args_parse(&a, v ? 3 : 1, (char **)argv, defs, e, sizeof(e)) < 0)
        return -2;
    r = xsvc_workers(&a, queue, windows, ncpu, out, err);
    args_free(&a);
    return r;
}

TEST(svc_workers)
{
    unsigned n = 0;
    sbuf err;
    sb_init(&err);
    CHECK_INT(workers(NULL, 310, 0, 8, &n, &err), 0);
    CHECK_INT(n, 1);
    CHECK_INT(workers("4", 310, 0, 1, &n, &err), 0);
    CHECK_INT(n, 4);
    CHECK_INT(workers("auto", 310, 0, 2, &n, &err), 0);
    CHECK_INT(n, 2);
    CHECK_INT(workers("auto", 310, 0, 16, &n, &err), 0);
    CHECK_INT(n, XSVC_AUTO_WORKERS);
    CHECK_INT(workers("auto", 310, 0, 0, &n, &err), 0);
    CHECK_INT(n, 1);
    CHECK_INT(workers("64", 310, 0, 1, &n, &err), 0);
    CHECK_INT(n, 64);
    CHECK_INT(workers("1", 310, 1, 8, &n, &err), 0); /* Windows: one is fine */
    CHECK_INT(n, 1);
    CHECK_INT(workers("65535", 0, 0, 1, &n, &err), -1);
    sb_reset(&err);
    {
        static const char *const bad[] = {"0", "65", "-1", "+2", "2x", "", "two"};
        for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
            CHECK_INT(workers(bad[i], 310, 0, 4, &n, &err), -1);
            CHECK(strstr(err.data, "bad --ext-workers") != NULL);
            sb_reset(&err);
        }
    }
    CHECK_INT(workers("2", 310, 1, 4, &n, &err), -1);
    CHECK(strstr(err.data, "Linux only") != NULL);
    sb_reset(&err);
    CHECK_INT(workers("4", 65533, 0, 4, &n, &err), -1);
    CHECK(strstr(err.data, "65535") != NULL);
    sb_reset(&err);
    CHECK_INT(workers("3", 65533, 0, 4, &n, &err), 0);
    sb_free(&err);
}

TEST(svc_options)
{
    xsvc s;
    sbuf err;
    sb_init(&err);
    CHECK_INT(xsvc_parse_uid("1000", &s), 0);
    CHECK_INT(s.uid, 1000);
    CHECK_INT(s.ngid, 1);
    CHECK_INT(s.gid[0], 1000);
    CHECK_INT(xsvc_parse_uid("5:6,7,8", &s), 0);
    CHECK_INT(s.uid, 5);
    CHECK_INT(s.ngid, 3);
    CHECK_INT(s.gid[2], 8);
    CHECK_INT(xsvc_parse_uid("", &s), -1);
    CHECK_INT(xsvc_parse_uid("x", &s), -1);
    CHECK_INT(xsvc_parse_uid("5:", &s), -1);
    CHECK_INT(xsvc_parse_uid("5:6,", &s), -1);
    CHECK_INT(xsvc_parse_uid("5;6", &s), -1);
    CHECK_INT(xsvc_parse_uid("4294967295", &s), -1);

    CHECK_INT(parse_run(&s, NULL, NULL, NULL, &err), 0);
    CHECK_INT(s.dry_run, 0);
    CHECK(s.pidfile == NULL);
#  ifdef PLAT_LINUX
    CHECK_INT(s.seccomp, 1);
#  else
    CHECK_INT(s.seccomp, 0);
#  endif
    CHECK_INT(parse_run(&s, "--dry-run", NULL, "--comment=x y", &err), 0);
    CHECK_INT(s.dry_run, 1);
    CHECK_INT(parse_run(&s, "--pidfile", "p.pid", NULL, &err), 0);
    CHECK_STR(s.pidfile, "p.pid");
    CHECK_INT(parse_run(&s, "--pidfile", "", NULL, &err), -1);
    sb_reset(&err);
    CHECK_INT(parse_run(&s, "--log-target", "stderr", NULL, &err), -1);
    sb_reset(&err);
    CHECK_INT(parse_run(&s, "--ext-seccomp=2", NULL, NULL, &err), -1);
    sb_reset(&err);
#  ifdef PLAT_LINUX
    CHECK_INT(parse_run(&s, "--log-target", "syslog", NULL, &err), 0);
    CHECK_INT(s.syslog, 1);
    CHECK_INT(parse_run(&s, "--ext-seccomp=0", NULL, NULL, &err), 0);
    CHECK_INT(s.seccomp, 0);
    CHECK_INT(parse_run(&s, "--ext-seccomp", NULL, NULL, &err), 0);
    CHECK_INT(s.seccomp, 1);
    CHECK_INT(parse_run(&s, "--uid", "x", NULL, &err), -1);
    sb_reset(&err);
    CHECK_INT(parse_run(&s, "--user", "geneva-no-such-user", NULL, &err), -1);
    CHECK_STR(err.data, "no user geneva-no-such-user");
    sb_reset(&err);
    CHECK_INT(parse_run(&s, "--uid", "1", "--user=root", &err), -1);
    sb_reset(&err);
    if (geteuid()) {
        CHECK_INT(parse_run(&s, "--uid", "1", NULL, &err), -1);
        CHECK_STR(err.data, "--user/--uid need root");
        sb_reset(&err);
        CHECK_INT(parse_run(&s, "--uid", "1", "--dry-run", &err), 0);
    } else {
        CHECK_INT(parse_run(&s, "--uid", "1:2", NULL, &err), 0);
        CHECK_INT(s.drop, 1);
        CHECK_INT(s.gid[0], 2);
        CHECK_INT(parse_run(&s, "--user", "root", NULL, &err), 0);
        CHECK_INT(s.uid, 0);
        CHECK_STR(s.user, "root");
    }
#  else
    CHECK_INT(parse_run(&s, "--daemon", NULL, NULL, &err), -1);
    sb_reset(&err);
    CHECK_INT(parse_run(&s, "--uid", "1", NULL, &err), -1);
    sb_reset(&err);
#  endif
    sb_free(&err);
}

TEST(svc_syslog)
{
    sbuf s;
    sb_init(&s);
    xsvc_syslog_format(&s, 0, "engine", "x", 42);
    CHECK_STR(s.data, "<27>geneva[42]: engine: x");
    sb_reset(&s);
    xsvc_syslog_format(&s, 1, "a", "b", 1);
    CHECK_STR(s.data, "<28>geneva[1]: a: b");
    sb_reset(&s);
    xsvc_syslog_format(&s, 2, "a", "b", 1);
    CHECK_STR(s.data, "<30>geneva[1]: a: b");
    sb_reset(&s);
    xsvc_syslog_format(&s, 4, "a", "b", 1);
    CHECK_STR(s.data, "<31>geneva[1]: a: b");
    sb_free(&s);
}

TEST(svc_notify)
{
    unsetenv("NOTIFY_SOCKET");
    CHECK_INT(xsvc_notify("READY=1"), 0); /* not under systemd */
#  ifdef PLAT_LINUX
    {
        const char *path = "geneva-test-notify.sock";
        struct sockaddr_un a;
        char buf[64], full[256];
        int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
        ssize_t n;
        CHECK(fd >= 0);
        if (!getcwd(full, sizeof(full) - 40))
            return;
        strcat(full, "/");
        strcat(full, path);
        if (strlen(full) >= sizeof(a.sun_path)) {
            close(fd);
            return;
        }
        unlink(full);
        memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        strcpy(a.sun_path, full);
        CHECK_INT(bind(fd, (struct sockaddr *)&a, sizeof(a)), 0);
        setenv("NOTIFY_SOCKET", full, 1);
        CHECK_INT(xsvc_notify("READY=1"), 0);
        n = recv(fd, buf, sizeof(buf) - 1, MSG_DONTWAIT);
        CHECK_INT(n, 7);
        if (n > 0) {
            buf[n] = 0;
            CHECK_STR(buf, "READY=1");
        }
        /* abstract */
        setenv("NOTIFY_SOCKET", "@geneva-test-no-such", 1);
        CHECK_INT(xsvc_notify("READY=1"), -1);
        setenv("NOTIFY_SOCKET", "relative", 1);
        CHECK_INT(xsvc_notify("READY=1"), -1);
        unsetenv("NOTIFY_SOCKET");
        close(fd);
        unlink(full);
    }
#  endif
}

#  ifdef PLAT_LINUX
/* exit 0: the call went; killed by SIGSYS: blocked; 3: no seccomp here */
static int in_seccomp(int which)
{
    pid_t pid;
    int st;
    fflush(NULL);
    pid = fork();
    if (!pid) {
        if (xsec_apply() < 0)
            _exit(3);
        if (which == 0) {
            getpid();
            if (open("/dev/null", 0) < 0)
                _exit(4);
            _exit(0);
        }
        if (which == 1) {
            char *const av[] = {(char *)"/bin/true", NULL};
            execv("/bin/true", av);
            _exit(5); /* not run: also a failure */
        }
        if (which == 2)
            kill(getppid(), 0);
        if (which == 3)
            mkdir("geneva-test-no-dir", 0700);
        _exit(0);
    }
    if (pid < 0 || waitpid(pid, &st, 0) < 0)
        return -1;
    if (WIFSIGNALED(st))
        return -WTERMSIG(st);
    return WEXITSTATUS(st);
}
#  endif

TEST(svc_seccomp)
{
    uint8_t prog[8 * 64];
    size_t n = xsec_program(prog, 64);
#  ifdef PLAT_LINUX
#    if defined(__x86_64__) || defined(__aarch64__) || defined(__i386__) || defined(__arm__) ||               \
        defined(__mips__) || defined(__powerpc__) || defined(__riscv) || defined(__loongarch64) ||        \
        defined(__s390x__)
    CHECK(n > 20);
    CHECK_INT(xsec_program(prog, 5), 0); /* too small */
    {
        /* the last two return: allow, kill */
        uint16_t code;
        uint32_t k;
        memcpy(&code, prog + 8 * (n - 1), 2);
        memcpy(&k, prog + 8 * (n - 1) + 4, 4);
        CHECK_INT(code, 0x06);
        CHECK_INT(k, 0x80000000u);
        memcpy(&k, prog + 8 * (n - 2) + 4, 4);
        CHECK_INT(k, 0x7fff0000u);
        /* every jump lands on the kill */
        for (size_t i = 0; i + 2 < n; i++) {
            memcpy(&code, prog + 8 * i, 2);
            if (code == 0x15 || code == 0x35) {
                size_t t = i + 1 + prog[8 * i + 2], f = i + 1 + prog[8 * i + 3];
                CHECK(t == n - 1 || t == i + 1);
                CHECK(f == n - 1 || f == i + 1);
            }
        }
    }
    {
        int r = in_seccomp(0);
        if (r == 3) {
            printf("  (no seccomp in this kernel: skipped)\n");
            return;
        }
        CHECK_INT(r, 0);
        CHECK_INT(in_seccomp(1), -SIGSYS);
        CHECK_INT(in_seccomp(2), -SIGSYS);
        CHECK_INT(in_seccomp(3), -SIGSYS);
    }
#    endif
#  else
    CHECK_INT(n, 0);
    CHECK_INT(xsec_apply(), -1);
#  endif
}

void suite_svc(void)
{
    RUN(svc_split);
    RUN(svc_expand);
    RUN(svc_options);
    RUN(svc_workers);
    RUN(svc_syslog);
    RUN(svc_notify);
    RUN(svc_seccomp);
}

#else
void suite_svc(void) {}
#endif
