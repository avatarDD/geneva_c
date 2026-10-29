/*
 * "geneva library": the built-in strategies of Geneva's library.py.
 *
 *   geneva library --country china --test http
 *   geneva library -q --censor 8b | geneva eval -f - ...
 */
#include <stdio.h>
#include <string.h>

#include "args.h"
#include "geneva.h"
#include "json.h"
#include "library.h"
#include "util.h"

int cmd_library(int argc, char **argv)
{
    static const optdef defs[] = {
        {"country", 'c', 1, "NAME", "china, india, kazakhstan, or lab"},
        {"test", 't', 1, "TYPE", "http, dns, dns_tcp, kazakhstan_injected_https, echo"},
        {"censor", 0, 1, "N", "lab strategies that beat censor N of \"geneva censor\""},
        {"client-side", 0, 0, NULL, "only strategies for the client"},
        {"server-side", 0, 0, NULL, "only strategies for the server"},
        {"min-rate", 0, 1, "PCT", "only strategies with at least this success rate"},
        {"all", 'a', 0, NULL, "also the lab strategies"},
        {"json", 0, 0, NULL, "JSON array"},
        {"strategies", 'q', 0, NULL, "strategies only, one per line (for eval -f)"},
        {"help", 'h', 0, NULL, "show help"},
        {NULL, 0, 0, NULL, NULL},
    };
    args_t a;
    char err[128];
    lib_filter f;
    size_t n, shown = 0;
    const lib_entry *v = library_entries(&n);
    int64_t rate;
    int json, quiet;
    sbuf sb;
    jw w;

    if (args_parse(&a, argc, argv, defs, err, sizeof(err)) < 0) {
        fprintf(stderr, "geneva library: %s\n", err);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "help")) {
        args_help("Usage: geneva library [options]\n"
                  "Lists the strategies of Geneva's library: the ones found against the censors\n"
                  "of China, India and Kazakhstan (with Geneva's success rates), and with --all\n"
                  "or --country lab the ones against the lab censors (docs/CENSOR.md).\n"
                  "Output: rate, country, test, side, strategy and description, tab-separated.",
                  defs);
        args_free(&a);
        return EXIT_OK;
    }
    if (a.npos) {
        fprintf(stderr, "geneva library: unexpected argument \"%s\"\n", a.pos[0]);
        args_free(&a);
        return EXIT_USAGE;
    }
    if (arg_has(&a, "client-side") && arg_has(&a, "server-side")) {
        fprintf(stderr, "geneva library: --client-side and --server-side exclude each other\n");
        args_free(&a);
        return EXIT_USAGE;
    }
    if (arg_int(&a, "min-rate", 0, 0, 100, &rate) < 0) {
        args_free(&a);
        return EXIT_USAGE;
    }
    memset(&f, 0, sizeof(f));
    f.country = arg_str(&a, "country", NULL);
    f.test_type = arg_str(&a, "test", NULL);
    f.censor = arg_str(&a, "censor", NULL);
    f.side = arg_has(&a, "client-side") ? 1 : arg_has(&a, "server-side") ? 2 : 0;
    f.min_rate = (int)rate;
    f.with_lab = arg_has(&a, "all");
    json = arg_has(&a, "json");
    quiet = arg_has(&a, "strategies");

    sb_init(&sb);
    jw_init(&w, &sb);
    if (json)
        jw_arr(&w);
    for (size_t i = 0; i < n; i++) {
        const lib_entry *e = &v[i];
        if (!library_match(e, &f))
            continue;
        shown++;
        if (json) {
            jw_obj(&w);
            jw_kstr(&w, "strategy", e->strategy);
            jw_kint(&w, "rate", e->rate);
            jw_kstr(&w, "country", e->country);
            jw_kstr(&w, "test", e->test_type);
            jw_kbool(&w, "server_side", e->server_side);
            jw_kstr(&w, "description", e->description);
            if (e->censors) {
                jw_key(&w, "censors");
                jw_arr(&w);
                for (const char *p = e->censors; *p;) {
                    size_t len = strcspn(p, " ");
                    jw_strn(&w, p, len);
                    p += len;
                    while (*p == ' ')
                        p++;
                }
                jw_arr_end(&w);
            }
            jw_obj_end(&w);
        } else if (quiet) {
            printf("%s\n", e->strategy);
        } else {
            printf("%d%%\t%s\t%s\t%s\t%s\t%s\n", e->rate, e->country, e->test_type,
                   e->server_side ? "server" : "client", e->strategy, e->description);
        }
    }
    if (json) {
        jw_arr_end(&w);
        printf("%s\n", sb.data);
    }
    sb_free(&sb);
    args_free(&a);
    return shown ? EXIT_OK : EXIT_FAIL;
}
