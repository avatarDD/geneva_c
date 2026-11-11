/*
 * "geneva selftest --ext": the fuzz targets of src/ext/fuzz.c run in the
 * binary itself (docs/EXT_ROADMAP.md, N6): every built-in seed, then N
 * mutations of them per target, reproducible from --seed. On POSIX each
 * target runs in a child process, so that a crash or a hang is reported
 * with the input that caused it instead of taking the command down.
 */
#include "ext/selftest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef _WIN32
#  include <direct.h>
#else
#  include <signal.h>
#  include <sys/mman.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

#include "args.h"
#include "ext/fuzz.h"
#include "ext_opt.h"
#include "geneva.h"
#include "json.h"
#include "plat.h"
#include "util.h"

typedef struct {
    uint8_t **v;
    size_t *n;
    size_t count;
} seedset;

static void seed_add(void *ud, const uint8_t *d, size_t n)
{
    seedset *s = ud;
    s->v = xrealloc(s->v, sizeof(*s->v) * (s->count + 1));
    s->n = xrealloc(s->n, sizeof(*s->n) * (s->count + 1));
    s->v[s->count] = xmalloc(n ? n : 1);
    memcpy(s->v[s->count], d, n);
    s->n[s->count++] = n;
}

static void seeds_free(seedset *s)
{
    for (size_t i = 0; i < s->count; i++)
        free(s->v[i]);
    free(s->v);
    free(s->n);
    memset(s, 0, sizeof(*s));
}

static uint64_t name_hash(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    while (*s)
        h = (h ^ (uint8_t)*s++) * 1099511628211ULL;
    return h;
}

/* Input i of target t: seed i, or after the seeds a mutation of one of
 * them that depends only on (seed, t, i); its length in buf (cap bytes) */
static size_t make_input(const xfuzz_target *t, const seedset *s, uint64_t seed, uint64_t i, uint8_t *buf, size_t cap)
{
    uint64_t rs;
    size_t b, o, n;
    int depth;
    if (i < s->count) {
        n = s->n[i] < cap ? s->n[i] : cap;
        memcpy(buf, s->v[i], n);
        return n;
    }
    rs = seed ^ name_hash(t->name) ^ (i * 0x9e3779b97f4a7c15ULL);
    (void)xfuzz_rand(&rs);
    if (!s->count)
        return 0;
    b = (size_t)(xfuzz_rand(&rs) % s->count);
    o = (size_t)(xfuzz_rand(&rs) % s->count);
    n = s->n[b] < cap ? s->n[b] : cap;
    memcpy(buf, s->v[b], n);
    depth = 1 + (int)(xfuzz_rand(&rs) % 8);
    for (int k = 0; k < depth; k++)
        n = xfuzz_mutate(buf, n, cap, &rs, s->v[o], s->n[o]);
    return n;
}

static int mkdir_one(const char *path)
{
#ifdef _WIN32
    if (_mkdir(path) == 0)
        return 0;
#else
    if (mkdir(path, 0755) == 0)
        return 0;
#endif
    {
        struct stat st;
        return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR ? 0 : -1;
    }
}

/* What became of one target */
typedef struct {
    const char *result; /* "ok", "crash", "hang", "error" */
    int sig;            /* the signal (crash, hang) or the exit code (error) */
    uint64_t input;     /* the input running when it failed */
    char *file;         /* where that input was saved (NULL: not saved) */
    uint64_t ms;
} outcome;

typedef struct {
    uint64_t seed, n;
    size_t max_len;
    int timeout;
    const char *crash_dir;
} run_opts;

static void run_inputs(const xfuzz_target *t, const seedset *s, const run_opts *o, volatile uint64_t *cur)
{
    uint8_t *buf = xmalloc(o->max_len ? o->max_len : 1);
    uint64_t total = s->count + o->n;
    for (uint64_t i = 0; i < total; i++) {
        size_t n = make_input(t, s, o->seed, i, buf, o->max_len);
        *cur = i;
#ifndef _WIN32
        if (o->timeout)
            alarm((unsigned)o->timeout);
#endif
        xfuzz_run(t, buf, n);
    }
#ifndef _WIN32
    alarm(0);
#endif
    free(buf);
}

static void run_target(const xfuzz_target *t, const run_opts *o, outcome *out)
{
    seedset s;
    uint64_t t0 = plat_now_ms();
    memset(&s, 0, sizeof(s));
    memset(out, 0, sizeof(*out));
    out->result = "ok";
    t->seeds(seed_add, &s);
#ifdef _WIN32
    {
        uint64_t cur = 0;
        run_inputs(t, &s, o, &cur);
    }
#else
    {
        volatile uint64_t *cur = mmap(NULL, sizeof(uint64_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS,
                                      -1, 0);
        pid_t pid;
        int st = 0;
        if (cur == MAP_FAILED) {
            out->result = "error";
            out->sig = -1;
            goto done;
        }
        *cur = 0;
        fflush(stdout);
        fflush(stderr);
        pid = fork();
        if (pid == 0) {
            signal(SIGALRM, SIG_DFL);
            run_inputs(t, &s, o, cur);
            _exit(0);
        }
        if (pid < 0 || waitpid(pid, &st, 0) < 0) {
            out->result = "error";
            out->sig = -1;
        } else if (WIFSIGNALED(st)) {
            out->sig = WTERMSIG(st);
            out->result = out->sig == SIGALRM ? "hang" : "crash";
            out->input = *cur;
        } else if (WEXITSTATUS(st)) {
            /* a sanitizer reports and exits */
            out->result = "crash";
            out->sig = -WEXITSTATUS(st);
            out->input = *cur;
        }
        munmap((void *)cur, sizeof(uint64_t));
    }
    if (strcmp(out->result, "ok") && strcmp(out->result, "error") && o->crash_dir) {
        /* the input is made again: it depends only on the seed */
        uint8_t *buf = xmalloc(o->max_len ? o->max_len : 1);
        size_t n = make_input(t, &s, o->seed, out->input, buf, o->max_len);
        char *path = xasprintf("%s/%s-%s-%llu-%llu.bin", o->crash_dir, out->result, t->name,
                               (unsigned long long)o->seed, (unsigned long long)out->input);
        if (mkdir_one(o->crash_dir) == 0 && write_file(path, buf, n) == 0)
            out->file = path;
        else
            free(path);
        free(buf);
    }
done:
#endif
    out->ms = plat_now_ms() - t0;
    seeds_free(&s);
}

static int write_seeds(const xfuzz_target *const *ts, size_t nt, const char *dir)
{
    if (mkdir_one(dir) < 0) {
        fprintf(stderr, "geneva selftest: cannot make %s\n", dir);
        return EXIT_IO;
    }
    for (size_t k = 0; k < nt; k++) {
        seedset s;
        char *sub = xasprintf("%s/%s", dir, ts[k]->name);
        memset(&s, 0, sizeof(s));
        ts[k]->seeds(seed_add, &s);
        if (mkdir_one(sub) < 0) {
            fprintf(stderr, "geneva selftest: cannot make %s\n", sub);
            free(sub);
            seeds_free(&s);
            return EXIT_IO;
        }
        for (size_t i = 0; i < s.count; i++) {
            char *p = xasprintf("%s/seed-%03zu", sub, i);
            int r = write_file(p, s.v[i], s.n[i]);
            if (r < 0)
                fprintf(stderr, "geneva selftest: cannot write %s\n", p);
            free(p);
            if (r < 0) {
                free(sub);
                seeds_free(&s);
                return EXIT_IO;
            }
        }
        printf("%s: %zu seeds\n", sub, s.count);
        free(sub);
        seeds_free(&s);
    }
    return EXIT_OK;
}

int xcmd_selftest(int argc, char **argv)
{
    static const optdef defs[] = {
        {"ext", 0, 0, NULL, "turn on the extensions (required)"},
        {"fuzz", 0, 1, "N", "N random inputs per target after the seeds (default 0: the seeds only)"},
        {"target", 't', 1, "LIST", "only these targets (comma-separated; see --list)"},
        {"seed", 0, 1, "S", "seed of the random inputs (default: from the clock; printed)"},
        {"max-len", 0, 1, "BYTES", "longest random input (default 4096)"},
        {"timeout", 0, 1, "SEC", "an input running longer is a hang (default 10, 0: none; not on Windows)"},
        {"crash-dir", 0, 1, "DIR", "save the input of a crash or hang there (for tests/fuzz/)"},
        {"seeds-out", 0, 1, "DIR", "write the seeds to DIR/TARGET/ for libFuzzer or AFL++ and exit"},
        {"list", 0, 0, NULL, "list the targets"},
        {"json", 0, 0, NULL, "print the result as JSON"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    size_t nall, nt = 0;
    const xfuzz_target *all, **ts = NULL;
    run_opts o;
    int64_t v;
    int rc = EXIT_OK, failed = 0, json;
    sbuf js;
    jw w;

    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva selftest: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva selftest --ext [--fuzz N] [options]\n"
                  "Runs the fuzz targets (every reader of packets, captures, strategies, lists,\n"
                  "profiles and option values) over their built-in seeds, then over N random\n"
                  "changes of them each. The same --seed gives the same inputs. Exit 0 when\n"
                  "every target passed, 1 when one crashed, hung or failed its own check.\n"
                  "The same targets build for libFuzzer and AFL++ (tests/fuzz/run.sh).",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (!arg_has(&a, "ext")) {
        fprintf(stderr, "geneva selftest: needs --ext\n");
        args_free(&a);
        return EXIT_USAGE;
    }
    if (a.npos) {
        fprintf(stderr, "geneva selftest: unexpected argument \"%s\"\n", a.pos[0]);
        args_free(&a);
        return EXIT_USAGE;
    }
    json = arg_has(&a, "json");
    memset(&o, 0, sizeof(o));
    all = xfuzz_targets(&nall);
    if (arg_has(&a, "list")) {
        for (size_t i = 0; i < nall; i++)
            printf("%-10s %s\n", all[i].name, all[i].what);
        args_free(&a);
        return EXIT_OK;
    }
    if (arg_int(&a, "fuzz", 0, 0, INT64_MAX / 2, &v) < 0)
        goto usage;
    o.n = (uint64_t)v;
    if (arg_int(&a, "max-len", 4096, 1, 1 << 20, &v) < 0)
        goto usage;
    o.max_len = (size_t)v;
    if (arg_int(&a, "timeout", 10, 0, 86400, &v) < 0)
        goto usage;
    o.timeout = (int)v;
    if (arg_has(&a, "seed")) {
        uint64_t sd;
        if (parse_u64(arg_str(&a, "seed", ""), &sd) < 0) {
            fprintf(stderr, "geneva selftest: bad --seed %s\n", arg_str(&a, "seed", ""));
            goto usage;
        }
        o.seed = sd;
    } else {
        o.seed = plat_now_ms() % 1000000000ULL;
    }
    o.crash_dir = arg_str(&a, "crash-dir", NULL);
    ts = xcalloc(nall, sizeof(*ts));
    if (arg_has(&a, "target")) {
        const char *s = arg_str(&a, "target", "");
        for (;;) {
            const char *e = strchr(s, ',');
            size_t l = e ? (size_t)(e - s) : strlen(s);
            char name[32];
            const xfuzz_target *t;
            if (l >= sizeof(name))
                l = sizeof(name) - 1;
            memcpy(name, s, l);
            name[l] = 0;
            if (!(t = xfuzz_find(name))) {
                fprintf(stderr, "geneva selftest: unknown target \"%s\" (see --list)\n", name);
                goto usage;
            }
            if (nt < nall)
                ts[nt++] = t;
            if (!e)
                break;
            s = e + 1;
        }
    } else {
        for (size_t i = 0; i < nall; i++)
            ts[nt++] = &all[i];
    }
    xfuzz_init();
    if (arg_has(&a, "seeds-out")) {
        rc = write_seeds(ts, nt, arg_str(&a, "seeds-out", "."));
        goto done;
    }

    sb_init(&js);
    jw_init(&w, &js);
    if (json) {
        jw_obj(&w);
        jw_kuint(&w, "seed", o.seed);
        jw_kuint(&w, "inputs", o.n);
        jw_key(&w, "targets");
        jw_arr(&w);
    } else {
        printf("geneva selftest: seed %llu, %llu random inputs per target\n", (unsigned long long)o.seed,
               (unsigned long long)o.n);
        fflush(stdout);
    }
    for (size_t k = 0; k < nt; k++) {
        outcome r;
        int ok;
        run_target(ts[k], &o, &r);
        ok = !strcmp(r.result, "ok");
        failed += !ok;
        if (json) {
            jw_obj(&w);
            jw_kstr(&w, "name", ts[k]->name);
            jw_kstr(&w, "result", r.result);
            jw_kuint(&w, "ms", r.ms);
            if (!ok) {
                jw_kint(&w, r.sig < 0 ? "exit" : "signal", r.sig < 0 ? -r.sig : r.sig);
                jw_kuint(&w, "input", r.input);
                if (r.file)
                    jw_kstr(&w, "file", r.file);
            }
            jw_obj_end(&w);
        } else {
            printf("  %-10s %-5s %6.2f s", ts[k]->name, r.result, (double)r.ms / 1000);
            if (!ok) {
                if (r.sig > 0)
                    printf(" (signal %d)", r.sig);
                else if (r.sig < 0)
                    printf(" (exit %d)", -r.sig);
                if (strcmp(r.result, "error"))
                    printf(" on input %llu", (unsigned long long)r.input);
                if (r.file)
                    printf(", saved to %s", r.file);
                printf("\n    again: geneva selftest --ext --target %s --seed %llu --fuzz %llu --max-len %zu",
                       ts[k]->name, (unsigned long long)o.seed, (unsigned long long)o.n, o.max_len);
            }
            printf("\n");
            fflush(stdout);
        }
        free(r.file);
    }
    if (json) {
        jw_arr_end(&w);
        jw_kbool(&w, "ok", !failed);
        jw_obj_end(&w);
        printf("%s\n", js.data);
    } else {
        if (failed)
            printf("geneva selftest: %d of %zu targets failed\n", failed, nt);
        else
            printf("geneva selftest: %zu targets ok\n", nt);
    }
    sb_free(&js);
    rc = failed ? EXIT_FAIL : EXIT_OK;
done:
    free(ts);
    args_free(&a);
    return rc;
usage:
    free(ts);
    args_free(&a);
    return EXIT_USAGE;
}
