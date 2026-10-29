/*
 * "geneva check": parse, validate and print strategies.
 * "geneva apply": run a strategy over a capture file offline.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "geneva.h"
#include "json.h"
#include "log.h"
#include "pcap.h"
#include "pkt.h"
#include "ports.h"
#include "rng.h"
#include "strategy.h"
#include "util.h"

/* ---- check --------------------------------------------------------------- */

static int check_one(const char *text, int pretty, int json, int quiet)
{
    sbuf err, out;
    strategy *s;
    sb_init(&err);
    sb_init(&out);
    s = strategy_parse(text, &err);
    if (json) {
        jw w;
        jw_init(&w, &out);
        if (s) {
            /* {"ok":true, ...strategy fields} */
            sbuf tmp;
            jw tw;
            sb_init(&tmp);
            jw_init(&tw, &tmp);
            strategy_json(s, &tw);
            sb_printf(&out, "{\"ok\":true,%s", tmp.data + 1);
            sb_free(&tmp);
        } else {
            jw_obj(&w);
            jw_kbool(&w, "ok", 0);
            jw_kstr(&w, "input", text);
            jw_kstr(&w, "error", err.data ? err.data : "");
            jw_obj_end(&w);
        }
        printf("%s\n", out.data);
    } else if (!s) {
        fprintf(stderr, "geneva check: %s\n  in: %s\n", err.data ? err.data : "parse error", text);
    } else if (!quiet) {
        if (pretty)
            strategy_pretty(s, &out);
        else
            strategy_print(s, &out);
        printf("%s\n", out.data);
    }
    sb_free(&err);
    sb_free(&out);
    if (!s)
        return -1;
    strategy_free(s);
    return 0;
}

int cmd_check(int argc, char **argv)
{
    static const optdef defs[] = {
        {"file", 'f', 1, "FILE", "read strategies from FILE, one per line (\"-\" = stdin)"},
        {"pretty", 'p', 0, NULL, "draw the action trees like Geneva's pretty_print()"},
        {"json", 0, 0, NULL, "one JSON object per strategy"},
        {"quiet", 'q', 0, NULL, "only report errors"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    int bad = 0, n = 0, idx = 0;
    const char *file;
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva check: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva check [options] STRATEGY...\n"
                  "Parses strategies and prints them in canonical form.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    for (int i = 0; i < a.npos; i++, n++)
        bad |= check_one(a.pos[i], arg_has(&a, "pretty"), arg_has(&a, "json"), arg_has(&a, "quiet"));
    while ((file = arg_next(&a, "file", &idx)) != NULL) {
        size_t len;
        char *data, *line, *next;
        if (!strcmp(file, "-")) {
            sbuf in;
            char chunk[4096];
            size_t got;
            sb_init(&in);
            while ((got = fread(chunk, 1, sizeof(chunk), stdin)) > 0)
                sb_append(&in, chunk, got);
            data = sb_take(&in);
        } else {
            data = read_file(file, &len);
        }
        if (!data) {
            fprintf(stderr, "geneva check: cannot read %s\n", file);
            args_free(&a);
            return EXIT_IO;
        }
        for (line = data; line && *line; line = next) {
            char *p;
            next = strchr(line, '\n');
            if (next)
                *next++ = 0;
            p = line;
            while (*p == ' ' || *p == '\t' || *p == '\r')
                p++;
            if (!*p || *p == '#')
                continue;
            n++;
            bad |= check_one(line, arg_has(&a, "pretty"), arg_has(&a, "json"), arg_has(&a, "quiet"));
        }
        free(data);
    }
    args_free(&a);
    if (!n) {
        fprintf(stderr, "geneva check: no strategy given (see --help)\n");
        return EXIT_USAGE;
    }
    return bad ? EXIT_STRATEGY : EXIT_OK;
}

/* ---- apply --------------------------------------------------------------- */

static void describe(gpkt *p, sbuf *out)
{
    sb_reset(out);
    pkt_describe(p, out);
}

static int load_strategy_text(const args_t *a, char **text)
{
    const char *s = arg_str(a, "strategy", NULL), *f = arg_str(a, "strategy-file", NULL);
    size_t len;
    if (!!s == !!f) {
        fprintf(stderr, "geneva apply: give exactly one of --strategy and --strategy-file\n");
        return EXIT_USAGE;
    }
    if (s) {
        *text = xstrdup(s);
        return EXIT_OK;
    }
    *text = read_file(f, &len);
    if (!*text) {
        fprintf(stderr, "geneva apply: cannot read %s\n", f);
        return EXIT_IO;
    }
    return EXIT_OK;
}

static void tree_stats_json(jw *w, atree **f, size_t n)
{
    jw_arr(w);
    for (size_t i = 0; i < n; i++) {
        sbuf s;
        sb_init(&s);
        tree_print(f[i], &s);
        jw_obj(w);
        jw_kstr(w, "tree", s.data);
        jw_kuint(w, "fired", f[i]->fired);
        jw_obj_end(w);
        sb_free(&s);
    }
    jw_arr_end(w);
}

int cmd_apply(int argc, char **argv)
{
    static const optdef defs[] = {
        {"strategy", 's', 1, "STRATEGY", "strategy to apply"},
        {"strategy-file", 0, 1, "FILE", "read the strategy from FILE"},
        {"input", 'i', 1, "PCAP", "input capture (pcap or pcapng, \"-\" = stdin)"},
        {"output", 'o', 1, "PCAP", "output capture (raw IP pcap, \"-\" = stdout)"},
        {"dir", 'd', 1, "out|in", "direction of every packet (default out)"},
        {"server-port", 'p', 1, "PORTS",
         "packets to these ports are outbound, from them inbound, the rest pass as is"},
        {"rng-seed", 0, 1, "N", "seed for corrupt/random values (reproducible output)"},
        {"json", 0, 0, NULL, "print a JSON summary to stdout"},
        {"verbose", 'v', 0, NULL, "log every packet and its result to stderr"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    sbuf e, line;
    char *text = NULL;
    strategy *st = NULL;
    pcap_reader *rd = NULL;
    pcap_writer *wr = NULL;
    portset ports = {.n = 0};
    int use_ports = 0, rc = EXIT_OK, verbose, r;
    strat_dir def_dir = DIR_OUT;
    int64_t seed = 0;
    uint64_t n_in = 0, n_out = 0, n_skipped = 0, n_changed = 0;
    pcap_rec rec;

    sb_init(&e);
    sb_init(&line);
    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva apply: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva apply -s STRATEGY -i IN.pcap [-o OUT.pcap] [options]\n"
                  "Runs every packet of a capture through a strategy, like the engine would.",
                  defs);
        goto done;
    }
    verbose = arg_has(&a, "verbose");
    if (!arg_has(&a, "input") || a.npos) {
        fprintf(stderr, "geneva apply: need --input (and no positional arguments)\n");
        rc = EXIT_USAGE;
        goto done;
    }
    if (arg_has(&a, "dir")) {
        const char *d = arg_str(&a, "dir", "out");
        if (!strcmp(d, "out"))
            def_dir = DIR_OUT;
        else if (!strcmp(d, "in"))
            def_dir = DIR_IN;
        else {
            fprintf(stderr, "geneva apply: --dir must be out or in\n");
            rc = EXIT_USAGE;
            goto done;
        }
    }
    if (arg_has(&a, "server-port")) {
        if (ports_parse(arg_str(&a, "server-port", ""), &ports) < 0) {
            fprintf(stderr, "geneva apply: bad --server-port\n");
            rc = EXIT_USAGE;
            goto done;
        }
        use_ports = 1;
    }
    if (arg_int(&a, "rng-seed", 0, 0, INT64_MAX, &seed) < 0) {
        rc = EXIT_USAGE;
        goto done;
    }
    if (seed)
        rng_global_seed((uint64_t)seed);
    rc = load_strategy_text(&a, &text);
    if (rc != EXIT_OK)
        goto done;
    st = strategy_parse(text, &e);
    if (!st) {
        fprintf(stderr, "geneva apply: %s\n", e.data);
        rc = EXIT_STRATEGY;
        goto done;
    }
    rd = pcap_open_read(arg_str(&a, "input", "-"), &e);
    if (!rd) {
        fprintf(stderr, "geneva apply: %s\n", e.data);
        rc = EXIT_IO;
        goto done;
    }
    if (arg_has(&a, "output")) {
        wr = pcap_open_write(arg_str(&a, "output", "-"), &e);
        if (!wr) {
            fprintf(stderr, "geneva apply: %s\n", e.data);
            rc = EXIT_IO;
            goto done;
        }
    }

    while ((r = pcap_next(rd, &rec, &e)) > 0) {
        gpkt *p;
        strat_dir dir = def_dir;
        pktlist out = {0};
        int fired = 0, pass = 0;
        n_in++;
        p = rec.ip ? pkt_parse(rec.ip, rec.ip_len) : NULL;
        if (!p) {
            n_skipped++;
            if (verbose)
                fprintf(stderr, "#%llu skipped: not an IP packet\n", (unsigned long long)n_in);
            continue;
        }
        if (use_ports) {
            int to = p->l4 != LAYER_NONE && ports_has(&ports, p->dport);
            int from = p->l4 != LAYER_NONE && ports_has(&ports, p->sport);
            if (to)
                dir = DIR_OUT;
            else if (from)
                dir = DIR_IN;
            else
                pass = 1;
        }
        if (verbose)
            describe(p, &line);
        if (pass) {
            pktlist_push(&out, p);
        } else {
            fired = strategy_apply(st, p, dir, &out);
            /* inbound packets cannot branch: the engine accepts the first
             * result (possibly modified) or drops the packet */
            if (dir == DIR_IN)
                while (out.n > 1)
                    pkt_free(out.v[--out.n]);
        }
        if (fired)
            n_changed++;
        if (verbose)
            fprintf(stderr, "#%llu %s %s -> %zu packet(s)%s\n", (unsigned long long)n_in,
                    pass ? "pass" : (dir == DIR_OUT ? "out" : "in"), line.data, out.n,
                    fired ? "" : " (no tree fired)");
        for (size_t i = 0; i < out.n; i++) {
            size_t len;
            uint8_t *b = pkt_bytes(out.v[i], &len);
            if (verbose && fired) {
                describe(out.v[i], &line);
                fprintf(stderr, "    -> %s\n", line.data);
                if (out.v[i]->sleep > 0)
                    fprintf(stderr, "       (after %g s)\n", out.v[i]->sleep);
            }
            if (!len) {
                fprintf(stderr, "geneva apply: #%llu: cannot build a result packet\n",
                        (unsigned long long)n_in);
            } else {
                if (wr)
                    pcap_write(wr, rec.ts_ns + (uint64_t)(out.v[i]->sleep * 1e9), b, len);
                n_out++;
            }
            free(b);
        }
        pktlist_free(&out);
    }
    if (r < 0) {
        fprintf(stderr, "geneva apply: %s\n", e.data);
        rc = EXIT_IO;
    }
    if (wr && pcap_close_write(wr) < 0) {
        fprintf(stderr, "geneva apply: write error on %s\n", arg_str(&a, "output", "-"));
        rc = EXIT_IO;
    }
    wr = NULL;
    if (arg_has(&a, "json")) {
        sbuf js;
        jw w;
        sb_init(&js);
        jw_init(&w, &js);
        jw_obj(&w);
        sb_reset(&line);
        strategy_print(st, &line);
        jw_kstr(&w, "strategy", line.data);
        jw_kuint(&w, "packets_in", n_in);
        jw_kuint(&w, "packets_out", n_out);
        jw_kuint(&w, "skipped", n_skipped);
        jw_kuint(&w, "triggered", n_changed);
        jw_key(&w, "out_trees");
        tree_stats_json(&w, st->out, st->nout);
        jw_key(&w, "in_trees");
        tree_stats_json(&w, st->in, st->nin);
        jw_obj_end(&w);
        printf("%s\n", js.data);
        sb_free(&js);
    } else if (!verbose && arg_has(&a, "output") && strcmp(arg_str(&a, "output", "-"), "-")) {
        fprintf(stderr, "geneva apply: %llu packets in, %llu out, %llu skipped\n",
                (unsigned long long)n_in, (unsigned long long)n_out, (unsigned long long)n_skipped);
    }
done:
    if (wr)
        pcap_close_write(wr);
    pcap_close_read(rd);
    strategy_free(st);
    free(text);
    sb_free(&e);
    sb_free(&line);
    args_free(&a);
    return rc;
}
