#include <stdio.h>
#include <string.h>

#include "ext_opt.h"

/* Set once per process by the command before any thread starts; later
 * stages pass the switch on in their own option structs. */
static int g_ext;

int ext_parse_args(const args_t *a, const char *cmd)
{
    int on = arg_has(a, "ext");
    if (on && !GENEVA_EXT) {
        fprintf(stderr, "geneva %s: this build has no --ext (built with EXT=0)\n", cmd);
        return -1;
    }
    for (int i = 0; i < a->nopts; i++) {
        const char *n = a->opts[i].def->name;
        if (!on && !strncmp(n, "ext-", 4)) {
            fprintf(stderr, "geneva %s: --%s needs --ext\n", cmd, n);
            return -1;
        }
    }
    g_ext = on;
    return 0;
}

int ext_enabled(void)
{
    return g_ext;
}

void ext_reset(void)
{
    g_ext = 0;
}
