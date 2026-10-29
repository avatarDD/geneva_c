/*
 * "geneva evolve": the genetic search (options named like Geneva's
 * evolve.py), and "geneva db": the strategy database.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#  include <direct.h>
#else
#  include <sys/stat.h>
#endif

#include "args.h"
#include "evolve.h"
#include "geneva.h"
#include "log.h"
#include "pcap.h"
#include "plat.h"
#include "rng.h"
#include "sdb.h"

/* ---- signals ------------------------------------------------------------- */

static volatile sig_atomic_t g_stop;

#ifdef _WIN32
static BOOL WINAPI on_console(DWORD type)
{
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop = 1;
        return TRUE;
    }
    return FALSE;
}
static void catch_stop(void) { SetConsoleCtrlHandler(on_console, TRUE); }
#else
static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}
static void catch_stop(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}
#endif

static int make_dir(const char *path)
{
#ifdef _WIN32
    return _mkdir(path) == 0 || errno == EEXIST ? 0 : -1;
#else
    return mkdir(path, 0755) == 0 || errno == EEXIST ? 0 : -1;
#endif
}

/* ---- evaluators available before the probes of stage 7 ------------------ */

/* --mock-eval TEXT: strategies containing TEXT succeed, shorter ones more.
 * Lets the GA, the checkpoint and the database be exercised offline. */
typedef struct {
    const char *want;
} mock_ctx;

static int mock_eval(void *ctx, ga_ind *inds, size_t n)
{
    mock_ctx *m = ctx;
    for (size_t i = 0; i < n; i++) {
        size_t len = strategy_len(inds[i].s);
        inds[i].fit = strstr(inds[i].str, m->want) ? 400.0 - 10.0 * (double)len : -100.0 - (double)len;
        LOGD("ga", "Fitness %g: %s", inds[i].fit, inds[i].str);
    }
    return 0;
}

/* ---- real packets for values (Geneva's canary captures) ----------------- */

static int load_packets(const char *path, gen_ctx *g)
{
    sbuf err;
    pcap_reader *r;
    pcap_rec rec;
    int rc;
    sb_init(&err);
    r = pcap_open_read(path, &err);
    if (!r) {
        fprintf(stderr, "geneva evolve: %s\n", err.data);
        sb_free(&err);
        return -1;
    }
    while ((rc = pcap_next(r, &rec, &err)) == 1 && g->nenv < 10000) {
        gpkt *p;
        if (!rec.ip)
            continue;
        p = pkt_parse(rec.ip, rec.ip_len);
        if (!p)
            continue;
        g->env = xrealloc(g->env, (g->nenv + 1) * sizeof(*g->env));
        g->env[g->nenv++] = p;
    }
    pcap_close_read(r);
    if (rc < 0) {
        fprintf(stderr, "geneva evolve: %s: %s\n", path, err.data);
        sb_free(&err);
        return -1;
    }
    sb_free(&err);
    LOGI("ga", "%zu packet(s) from %s will seed values", g->nenv, path);
    return 0;
}

/* ---- geneva evolve ------------------------------------------------------- */

#define LOG_OPTS                                                                                    \
    {"log-level", 'l', 1, "LEVEL", "error, warn, info (default), debug or trace"},                  \
        {"log-format", 0, 1, "FMT", "text (default) or json"},                                      \
        {"log-file", 0, 1, "FILE", "also write the log to FILE"},                                   \
        {"verbose", 'v', 0, NULL, "same as --log-level trace"},                                     \
        {"quiet", 0, 0, NULL, "no log on stderr"},                                                  \
        {"events", 'e', 1, "SINK", "JSON Lines events: - (stdout), stderr, FILE or none"}

int cmd_evolve(int argc, char **argv)
{
    static const optdef defs[] = {
        {"in-trees", 0, 1, "N", "inbound trees per new strategy (default 0: no inbound forest)"},
        {"out-trees", 0, 1, "N", "outbound trees per new strategy (default 1)"},
        {"in-actions", 0, 1, "N", "actions per new inbound tree (default 2)"},
        {"out-actions", 0, 1, "N", "actions per new outbound tree (default 2)"},
        {"fix-trigger", 0, 1, "TRIGGER", "use this trigger in every tree (e.g. TCP:flags:PA)"},
        {"seed", 0, 1, "STRATEGY", "start every individual from this strategy"},
        {"load-from", 0, 1, "FILE", "start from a generation file (one strategy per line)"},
        {"population", 0, 1, "N", "population size (default 250)"},
        {"generations", 0, 1, "N", "generations to run (default 50)"},
        {"elite-clones", 0, 1, "N", "copies of the best individual kept (default 3)"},
        {"mutation-pb", 0, 1, "P", "mutation probability (default 0.99)"},
        {"crossover-pb", 0, 1, "P", "crossover probability (default 0.4)"},
        {"allowed-retries", 0, 1, "N", "times a strategy may be generated again (default 20)"},
        {"no-reject-empty", 0, 0, NULL, "keep mutations that leave no actions"},
        {"protos", 0, 1, "LIST", "protocols the GA may use (default TCP)"},
        {"fields", 0, 1, "LIST", "only these header fields"},
        {"disable-fields", 0, 1, "LIST", "never these header fields"},
        {"disable-action", 0, 1, "LIST", "never these actions (default sleep,trace)"},
        {"no-gas", 0, 0, NULL, "triggers never get gas"},
        {"packets", 0, 1, "PCAP", "real packets to draw trigger and tamper values from"},
        {"no-eval", 0, 0, NULL, "do not evaluate (every fitness is 0), for debugging"},
        {"mock-eval", 0, 1, "TEXT", "testing: strategies containing TEXT succeed"},
        {"output-dir", 'o', 1, "DIR", "write generationN.txt and hallN.txt here"},
        {"checkpoint", 0, 1, "FILE", "save the search here before every generation"},
        {"resume", 0, 0, NULL, "continue the search saved in --checkpoint"},
        {"resume-force", 0, 0, NULL, "resume even if the search settings changed"},
        {"db", 0, 1, "FILE", "strategy database: record evaluations, seed from the best"},
        {"target", 0, 1, "NAME", "target profile for the database (e.g. http:example.com)"},
        {"db-seed", 0, 1, "N", "seed up to N individuals from the database (default 10)"},
        {"top", 0, 1, "N", "print the N best strategies at the end (default 5)"},
        {"print-hall", 0, 0, NULL, "log the whole hall of fame at the end"},
        {"rng-seed", 0, 1, "N", "seed for reproducible runs"},
        LOG_OPTS,
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[160];
    ga_opts o;
    hall_of_fame hall;
    trigger fixed;
    mock_ctx mock;
    sbuf msg, params;
    int64_t v;
    int rc = EXIT_USAGE, have_fixed = 0;
    const char *s, *protos, *fields, *dfields, *dact;
    sdb *db = NULL;

    memset(&fixed, 0, sizeof(fixed));
    sb_init(&msg);
    sb_init(&params);
    hof_init(&hall);
    ga_opts_default(&o);
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva evolve: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva evolve [options]\n"
                  "Searches for strategies with Geneva's genetic algorithm. Ctrl+C stops after the\n"
                  "current step; with --checkpoint the search continues later with --resume.\n"
                  "Probes that evaluate strategies against a real censor come in a later stage;\n"
                  "until then use --no-eval or --mock-eval.",
                  defs);
        rc = EXIT_OK;
        goto done;
    }
    if (a.npos) {
        fprintf(stderr, "geneva evolve: unexpected argument \"%s\"\n", a.pos[0]);
        goto done;
    }
    if (parse_logging(&a, "evolve") < 0)
        goto done;
#define INT_OPT(name, field, lo, hi)                                                                \
    if (arg_int(&a, name, o.field, lo, hi, &v) < 0)                                                 \
        goto done;                                                                                  \
    o.field = (int)v;
    INT_OPT("in-trees", in_trees, 0, 16)
    INT_OPT("out-trees", out_trees, 0, 16)
    INT_OPT("in-actions", in_actions, 0, 32)
    INT_OPT("out-actions", out_actions, 0, 32)
    INT_OPT("population", population, 1, 1000000)
    INT_OPT("generations", generations, 0, 1000000)
    INT_OPT("elite-clones", elite_clones, 0, 1000000)
    INT_OPT("allowed-retries", allowed_retries, 1, 1000000)
    INT_OPT("db-seed", db_seed, 0, 1000000)
#undef INT_OPT
    if (arg_dbl(&a, "mutation-pb", o.mutation_pb, 0, 1, &o.mutation_pb) < 0 ||
        arg_dbl(&a, "crossover-pb", o.crossover_pb, 0, 1, &o.crossover_pb) < 0)
        goto done;
    if (!arg_has(&a, "db-seed"))
        o.db_seed = 10;
    o.no_reject_empty = arg_has(&a, "no-reject-empty");
    o.gen.no_gas = arg_has(&a, "no-gas");
    o.seed = arg_str(&a, "seed", NULL);
    o.load_from = arg_str(&a, "load-from", NULL);
    o.out_dir = arg_str(&a, "output-dir", NULL);
    o.checkpoint = arg_str(&a, "checkpoint", NULL);
    o.resume = arg_has(&a, "resume") || arg_has(&a, "resume-force");
    o.resume_force = arg_has(&a, "resume-force");
    o.target = arg_str(&a, "target", "");
    o.stop = &g_stop;
    if (o.resume && !o.checkpoint) {
        fprintf(stderr, "geneva evolve: --resume needs --checkpoint FILE\n");
        goto done;
    }
    if (o.seed && o.load_from) {
        fprintf(stderr, "geneva evolve: --seed and --load-from exclude each other\n");
        goto done;
    }
    if (arg_int(&a, "rng-seed", 0, 0, INT64_MAX, &v) < 0)
        goto done;
    if (v)
        rng_global_seed((uint64_t)v);

    /* the search space */
    protos = arg_str(&a, "protos", "TCP");
    fields = arg_str(&a, "fields", "");
    dfields = arg_str(&a, "disable-fields", "");
    dact = arg_str(&a, "disable-action", "sleep,trace");
    if (fields_restrict(protos, fields, dfields, &msg) < 0) {
        fprintf(stderr, "geneva evolve: %s\n", msg.data);
        goto done;
    }
    if (msg.len)
        LOGW("ga", "%s", msg.data);
    memset(o.gen.disabled, 0, sizeof(o.gen.disabled));
    sb_reset(&msg);
    if (gen_disable_actions(&o.gen, dact, &msg) < 0) {
        fprintf(stderr, "geneva evolve: %s\n", msg.data);
        goto done;
    }
    if ((s = arg_str(&a, "fix-trigger", NULL)) != NULL) {
        sb_reset(&msg);
        if (trigger_parse(&fixed, s, &msg) < 0) {
            fprintf(stderr, "geneva evolve: --fix-trigger: %s\n", msg.data);
            goto done;
        }
        have_fixed = 1;
        o.gen.fixed = &fixed;
    }
    sb_printf(&params, "protos=%s;fields=%s;disable-fields=%s;disable-action=%s;fix=%s;gas=%d;target=%s",
              protos, fields, dfields, dact, s ? s : "", !o.gen.no_gas, o.target);
    o.params = params.data;
    if ((s = arg_str(&a, "packets", NULL)) != NULL && load_packets(s, &o.gen) < 0) {
        rc = EXIT_IO;
        goto done;
    }

    /* evaluation */
    if (arg_has(&a, "mock-eval")) {
        mock.want = arg_str(&a, "mock-eval", "");
        o.eval = mock_eval;
        o.eval_ctx = &mock;
    } else if (!arg_has(&a, "no-eval")) {
        fprintf(stderr, "geneva evolve: no evaluator yet: the probes come in a later stage; use --no-eval "
                        "(or --mock-eval TEXT for testing)\n");
        goto done;
    }

    if (o.out_dir && make_dir(o.out_dir) < 0) {
        fprintf(stderr, "geneva evolve: cannot create %s\n", o.out_dir);
        rc = EXIT_IO;
        goto done;
    }
    if ((s = arg_str(&a, "db", getenv("GENEVA_DB"))) != NULL && *s) {
        sb_reset(&msg);
        db = sdb_open(s, &msg);
        if (!db) {
            fprintf(stderr, "geneva evolve: %s\n", msg.data);
            rc = EXIT_IO;
            goto done;
        }
        o.db = db;
    }

    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "start");
        jw_kint(&ev.w, "proto", GENEVA_PROTO_VERSION);
        jw_kstr(&ev.w, "version", GENEVA_VERSION);
        jw_kstr(&ev.w, "mode", "evolve");
        jw_kint(&ev.w, "pid", plat_getpid());
        jw_kint(&ev.w, "population", o.population);
        jw_kint(&ev.w, "generations", o.generations);
        jw_kstr(&ev.w, "target", o.target);
        jw_kbool(&ev.w, "resume", o.resume);
        ev_emit(&ev);
    }
    LOGI("ga", "Initializing %d strategies with %d input-action trees and %d output-action trees of input "
               "size %d and output size %d for evolution over %d generations.",
         o.population, o.in_trees, o.out_trees, o.in_actions, o.out_actions, o.generations);
    catch_stop();
    rc = ga_run(&o, &hall);

    if (rc == EXIT_OK) {
        const hof_entry *best[64];
        int64_t top;
        size_t n;
        if (arg_int(&a, "top", 5, 0, 64, &top) < 0)
            top = 5;
        if (arg_has(&a, "print-hall")) {
            sbuf h;
            sb_init(&h);
            hof_format(&hall, &h);
            LOGI("ga", "\n%s", h.data);
            sb_free(&h);
        }
        n = hof_best(&hall, best, (size_t)top);
        for (size_t i = 0; i < n; i++) {
            double sum = 0;
            for (size_t k = 0; k < best[i]->n; k++)
                sum += best[i]->fits[k];
            printf("%g\t%zu\t%s\n", sum / (double)best[i]->n, best[i]->n, best[i]->str);
        }
        fflush(stdout);
        if (ev_enabled()) {
            ev_t ev;
            ev_begin(&ev, "result");
            jw_kbool(&ev.w, "stopped", g_stop != 0);
            jw_key(&ev.w, "best");
            jw_arr(&ev.w);
            for (size_t i = 0; i < n; i++) {
                double sum = 0;
                for (size_t k = 0; k < best[i]->n; k++)
                    sum += best[i]->fits[k];
                jw_obj(&ev.w);
                jw_kstr(&ev.w, "strategy", best[i]->str);
                jw_kdbl(&ev.w, "avg_fitness", sum / (double)best[i]->n);
                jw_kuint(&ev.w, "runs", best[i]->n);
                jw_obj_end(&ev.w);
            }
            jw_arr_end(&ev.w);
            ev_emit(&ev);
        }
    }
    if (ev_enabled()) {
        ev_t ev;
        ev_begin(&ev, "exit");
        jw_kint(&ev.w, "code", rc);
        jw_kstr(&ev.w, "reason", rc != EXIT_OK ? "error" : g_stop ? "signal" : "done");
        ev_emit(&ev);
    }
done:
    sdb_close(db);
    hof_free(&hall);
    if (have_fixed)
        trigger_clear(&fixed);
    for (size_t i = 0; i < o.gen.nenv; i++)
        pkt_free(o.gen.env[i]);
    free(o.gen.env);
    fields_reset_restrictions();
    sb_free(&msg);
    sb_free(&params);
    args_free(&a);
    return rc;
}

/* ---- geneva db ----------------------------------------------------------- */

static void print_rec_line(const sdb_rec *r)
{
    printf("%5.1f%%  %6llu  %9.2f  %9.2f  %-20s  %s\n", r->runs ? 100.0 * (double)r->ok / (double)r->runs : 0.0,
           (unsigned long long)r->runs, r->runs ? r->fit_sum / (double)r->runs : 0.0, r->fit_best,
           *r->t ? r->t : "-", r->s);
}

int cmd_db(int argc, char **argv)
{
    static const optdef defs[] = {
        {"db", 0, 1, "FILE", "database file (default $GENEVA_DB)"},
        {"target", 't', 1, "NAME", "only this target profile"},
        {"limit", 'n', 1, "N", "top: how many (default 10)"},
        {"json", 0, 0, NULL, "list/top/show: JSON Lines (the file format)"},
        {"format", 0, 1, "FMT", "export: jsonl (default) or txt (strategies only)"},
        {"min-runs", 0, 1, "N", "prune: drop records with fewer runs"},
        {"failed", 0, 0, NULL, "prune: drop strategies that never succeeded"},
        {"older-than", 0, 1, "DAYS", "prune: drop records not seen for DAYS days"},
        {"log-level", 'l', 1, "LEVEL", "error, warn, info (default), debug"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[160];
    const char *path, *cmd, *target;
    sbuf msg;
    sdb *db = NULL;
    int rc = EXIT_USAGE, json;

    sb_init(&msg);
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva db: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva db [--db FILE] COMMAND [args]\n"
                  "Commands:\n"
                  "  list              every record (success rate, runs, average and best fitness)\n"
                  "  top               the best strategies, -n N, per --target\n"
                  "  show STRATEGY     the records of one strategy\n"
                  "  export [FILE]     write records (or --format txt: strategies) to FILE or stdout\n"
                  "  import FILE...    merge database files or plain strategy lists\n"
                  "  prune             drop records by --min-runs, --failed, --older-than\n"
                  "  compact           rewrite the file with one line per record",
                  defs);
        rc = EXIT_OK;
        goto done;
    }
    if (parse_logging(&a, "db") < 0)
        goto done;
    if (!a.npos) {
        fprintf(stderr, "geneva db: need a command (see --help)\n");
        goto done;
    }
    cmd = a.pos[0];
    path = arg_str(&a, "db", getenv("GENEVA_DB"));
    if (!path || !*path) {
        fprintf(stderr, "geneva db: give --db FILE (or set GENEVA_DB)\n");
        goto done;
    }
    target = arg_str(&a, "target", NULL);
    json = arg_has(&a, "json");
    db = sdb_open(path, &msg);
    if (!db) {
        fprintf(stderr, "geneva db: %s\n", msg.data);
        rc = EXIT_IO;
        goto done;
    }
    rc = EXIT_OK;
    if (!strcmp(cmd, "list") || !strcmp(cmd, "top")) {
        int64_t lim = 0;
        size_t n;
        const sdb_rec **v;
        if (!strcmp(cmd, "top") && arg_int(&a, "limit", 10, 1, 1000000, &lim) < 0) {
            rc = EXIT_USAGE;
            goto done;
        }
        v = xmalloc((sdb_count(db) + 1) * sizeof(*v));
        n = sdb_top(db, target, v, lim ? (size_t)lim : sdb_count(db));
        if (!json && n)
            printf("%6s  %6s  %9s  %9s  %-20s  %s\n", "ok", "runs", "avg", "best", "target", "strategy");
        for (size_t i = 0; i < n; i++) {
            if (json) {
                sbuf s;
                sb_init(&s);
                sdb_rec_json(v[i], &s);
                printf("%s\n", s.data);
                sb_free(&s);
            } else {
                print_rec_line(v[i]);
            }
        }
        free(v);
    } else if (!strcmp(cmd, "show")) {
        int found = 0;
        if (a.npos != 2) {
            fprintf(stderr, "geneva db: show needs one strategy\n");
            rc = EXIT_USAGE;
            goto done;
        }
        {
            /* accept any spelling: compare canonical forms */
            strategy *st = strategy_parse(a.pos[1], &msg);
            char *canon = NULL;
            if (!st || strategy_canon(&st, &canon) < 0) {
                fprintf(stderr, "geneva db: %s\n", msg.len ? msg.data : "bad strategy");
                strategy_free(st);
                rc = EXIT_STRATEGY;
                goto done;
            }
            for (size_t i = 0; i < sdb_count(db); i++) {
                const sdb_rec *r = sdb_get(db, i);
                if (strcmp(r->s, canon) || (target && strcmp(r->t, target)))
                    continue;
                found = 1;
                if (json) {
                    sbuf s;
                    sb_init(&s);
                    sdb_rec_json(r, &s);
                    printf("%s\n", s.data);
                    sb_free(&s);
                } else {
                    print_rec_line(r);
                }
            }
            free(canon);
            strategy_free(st);
        }
        if (!found)
            rc = EXIT_FAIL;
    } else if (!strcmp(cmd, "export")) {
        const char *fmt = arg_str(&a, "format", "jsonl");
        FILE *f = stdout;
        if (strcmp(fmt, "jsonl") && strcmp(fmt, "txt")) {
            fprintf(stderr, "geneva db: --format must be jsonl or txt\n");
            rc = EXIT_USAGE;
            goto done;
        }
        if (a.npos > 1 && !(f = fopen(a.pos[1], "wb"))) {
            fprintf(stderr, "geneva db: cannot write %s\n", a.pos[1]);
            rc = EXIT_IO;
            goto done;
        }
        {
            const sdb_rec **v = xmalloc((sdb_count(db) + 1) * sizeof(*v));
            size_t n = sdb_top(db, target, v, sdb_count(db));
            for (size_t i = 0; i < n; i++) {
                if (!strcmp(fmt, "txt")) {
                    fprintf(f, "%s\n", v[i]->s);
                } else {
                    sbuf s;
                    sb_init(&s);
                    sdb_rec_json(v[i], &s);
                    fprintf(f, "%s\n", s.data);
                    sb_free(&s);
                }
            }
            free(v);
        }
        if (f != stdout && fclose(f) != 0)
            rc = EXIT_IO;
    } else if (!strcmp(cmd, "import")) {
        size_t added = 0, bad = 0;
        for (int i = 1; i < a.npos; i++) {
            size_t len;
            char *text = read_file(a.pos[i], &len), *line, *next;
            if (!text) {
                fprintf(stderr, "geneva db: cannot read %s\n", a.pos[i]);
                rc = EXIT_IO;
                continue;
            }
            for (line = text; line && *line; line = next) {
                sdb_rec r;
                char *end;
                next = strchr(line, '\n');
                if (next)
                    *next++ = 0;
                end = line + strlen(line);
                while (end > line && (end[-1] == '\r' || end[-1] == ' '))
                    *--end = 0;
                if (!*line || *line == '#')
                    continue;
                if (*line == '{') {
                    if (sdb_rec_parse(line, &r) < 0) {
                        bad++;
                        continue;
                    }
                } else {
                    /* a plain strategy: known, but never run */
                    memset(&r, 0, sizeof(r));
                    r.s = xstrdup(line);
                    r.t = xstrdup(target ? target : "");
                }
                {
                    /* store canonical strategies only */
                    sbuf e;
                    strategy *st;
                    char *canon = NULL;
                    sb_init(&e);
                    st = strategy_parse(r.s, &e);
                    sb_free(&e);
                    if (!st || strategy_canon(&st, &canon) < 0) {
                        strategy_free(st);
                        sdb_rec_free(&r);
                        bad++;
                        continue;
                    }
                    strategy_free(st);
                    free(r.s);
                    r.s = canon;
                }
                if (sdb_merge(db, &r) == 0)
                    added++;
                else
                    rc = EXIT_IO;
                sdb_rec_free(&r);
            }
            free(text);
        }
        if (a.npos < 2) {
            fprintf(stderr, "geneva db: import needs files\n");
            rc = EXIT_USAGE;
        }
        fprintf(stderr, "imported %zu record(s)%s", added, bad ? "" : "\n");
        if (bad)
            fprintf(stderr, ", skipped %zu bad line(s)\n", bad);
    } else if (!strcmp(cmd, "prune")) {
        int64_t min_runs, days;
        long n;
        if (arg_int(&a, "min-runs", 0, 0, INT64_MAX, &min_runs) < 0 ||
            arg_int(&a, "older-than", 0, 0, 100000, &days) < 0) {
            rc = EXIT_USAGE;
            goto done;
        }
        n = sdb_prune(db, (uint64_t)min_runs, arg_has(&a, "failed"), (uint64_t)days * 86400000ull);
        if (n < 0)
            rc = EXIT_IO;
        else
            fprintf(stderr, "removed %ld record(s), %zu left\n", n, sdb_count(db));
    } else if (!strcmp(cmd, "compact")) {
        if (sdb_compact(db) < 0)
            rc = EXIT_IO;
    } else {
        fprintf(stderr, "geneva db: unknown command \"%s\" (see --help)\n", cmd);
        rc = EXIT_USAGE;
    }
done:
    sdb_close(db);
    sb_free(&msg);
    args_free(&a);
    return rc;
}
