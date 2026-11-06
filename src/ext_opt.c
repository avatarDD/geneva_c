#include <stdio.h>
#include <string.h>

#include "ext_opt.h"
#if GENEVA_EXT
#  include "ext/ext.h"
#endif

/* Set once per process by the command before any thread starts; later
 * stages pass the switch on in their own option structs. */
static int g_ext;

/* the options of EXT_PROFILE_OPTS without the "ext-" prefix */
static const char *const ext_only[] = {"new",        "name",       "skip",        "template",   "import",
                                       "filter-l3",  "filter-tcp", "filter-udp",  "filter-icmp", "filter-ipp",
                                       "filter-l7",  "filter-mark"};

static int is_ext_only(const char *n)
{
    if (!strncmp(n, "ext-", 4))
        return 1;
    for (size_t i = 0; i < sizeof(ext_only) / sizeof(*ext_only); i++)
        if (!strcmp(n, ext_only[i]))
            return 1;
    return 0;
}

args_t ext_cmd_args(const args_t *a)
{
    args_t v = *a;
    for (int i = 0; i < a->nopts; i++)
        if (!strcmp(a->opts[i].def->name, "new")) {
            v.nopts = i;
            break;
        }
    return v;
}

int ext_parse_args(const args_t *a, const char *cmd)
{
    int on = arg_has(a, "ext");
    if (on && !GENEVA_EXT) {
        fprintf(stderr, "geneva %s: this build has no --ext (built with EXT=0)\n", cmd);
        return -1;
    }
    for (int i = 0; i < a->nopts; i++) {
        const char *n = a->opts[i].def->name;
        if (!on && is_ext_only(n)) {
            fprintf(stderr, "geneva %s: --%s needs --ext\n", cmd, n);
            return -1;
        }
    }
    g_ext = on;
#if GENEVA_EXT
    if (on && ext_activate(a, cmd) < 0)
        return -1;
#endif
    return 0;
}

int ext_enabled(void)
{
    return g_ext;
}

void ext_reset(void)
{
    g_ext = 0;
#if GENEVA_EXT
    ext_deactivate();
#endif
}
