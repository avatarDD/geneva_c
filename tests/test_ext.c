/* The --ext switch (stage X0 of docs/EXT_ROADMAP.md). */
#include <string.h>

#include "args.h"
#include "ext_opt.h"
#include "test.h"
#if GENEVA_EXT
#  include "ext/ext.h"
#endif

static const optdef defs[] = {
    {"strategy", 's', 1, "S", ""},
    {"ext-dummy", 0, 1, "N", "an --ext-* option as later stages add them"},
    EXT_OPT,
    {NULL, 0, 0, NULL, NULL},
};

/* args_parse + ext_parse_args on a NULL-terminated argv */
static int parse(const char **argv)
{
    args_t a;
    char err[128];
    int argc = 0, rc;
    while (argv[argc])
        argc++;
    if (args_parse(&a, argc, (char **)argv, defs, err, sizeof(err)) < 0)
        return -2;
    rc = ext_parse_args(&a, "test");
    args_free(&a);
    return rc;
}

static void test_switch(void)
{
    t_current = "ext switch";
    ext_reset();
    {
        const char *v[] = {"-s", "\\/", NULL};
        CHECK_INT(parse(v), 0);
        CHECK_INT(ext_enabled(), 0);
    }
    {
        /* an --ext-* option without --ext is a usage error */
        const char *v[] = {"--ext-dummy", "1", NULL};
        CHECK_INT(parse(v), -1);
        CHECK_INT(ext_enabled(), 0);
    }
    {
        const char *v[] = {"--ext", "--ext-dummy", "1", NULL};
        CHECK_INT(parse(v), GENEVA_EXT ? 0 : -1);
        CHECK_INT(ext_enabled(), GENEVA_EXT);
    }
    {
        /* the option may come anywhere */
        const char *v[] = {"--ext-dummy", "1", "-s", "\\/", "--ext", NULL};
        CHECK_INT(parse(v), GENEVA_EXT ? 0 : -1);
    }
    {
        /* a later command without --ext turns it off again */
        const char *v[] = {"-s", "\\/", NULL};
        CHECK_INT(parse(v), 0);
        CHECK_INT(ext_enabled(), 0);
    }
#if GENEVA_EXT
    t_current = "ext features";
    CHECK_STR(ext_features[0], "ext");
    {
        int n = 0;
        for (const char *const *f = ext_features; *f; f++, n++)
            CHECK(!strcmp(*f, "ext") || !strncmp(*f, "ext_", 4)); /* tests/golden strips these */
        CHECK(n >= 1);
    }
#endif
    ext_reset();
}

void suite_ext(void)
{
    test_switch();
}
