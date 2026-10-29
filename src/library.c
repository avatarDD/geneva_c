/*
 * The built-in strategy library (see library.h).
 */
#include "library.h"

#include <string.h>

#include "util.h"

#include "library_data.h"

const lib_entry *library_entries(size_t *n)
{
    *n = ARRAY_LEN(lib_entries);
    return lib_entries;
}

/* Whether the space-separated list has word w. */
static int has_word(const char *list, const char *w)
{
    size_t n = strlen(w);
    for (const char *p = list; p && *p;) {
        const char *end = strchr(p, ' ');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        if (len == n && !memcmp(p, w, n))
            return 1;
        p = end ? end + 1 : NULL;
    }
    return 0;
}

int library_match(const lib_entry *e, const lib_filter *f)
{
    int lab = !strcmp(e->country, "lab");
    if (f->country ? strcmp(e->country, f->country) != 0 : (lab && !f->with_lab && !f->censor))
        return 0;
    if (f->test_type && strcmp(e->test_type, f->test_type))
        return 0;
    if (f->censor) {
        const char *c = f->censor;
        if (!strncmp(c, "censor", 6))
            c += 6;
        if (!has_word(e->censors, c))
            return 0;
    }
    if ((f->side == 1 && e->server_side) || (f->side == 2 && !e->server_side))
        return 0;
    return e->rate >= f->min_rate;
}
