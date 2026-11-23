/* The profiles at run time (stage X6c): ctl set_strategy with "profile" and
 * ctl reload of the --ext-profile files, over the extension control hook the
 * engine calls — the same code the control socket reaches, with no NFQUEUE. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "args.h"
#include "engine_int.h"
#include "ext_opt.h"
#include "json.h"
#include "test.h"
#include "util.h"

#if GENEVA_EXT
#  include "ext/ext.h"

static int r_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    (void)w, (void)pctx, (void)accept, (void)data, (void)len;
    return 0;
}

static int r_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    (void)w, (void)pctx, (void)data, (void)len;
    return 0;
}

static const backend rbe = {
    "fake", sizeof(uint32_t), NULL, NULL, NULL, NULL, NULL, r_verdict, r_inject, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
};

/* A file next to the binary: the test runs from the repository's root.
 * A handful of buffers: callers keep the returned path while they make
 * another one. */
static const char *rt_file(const char *name, const char *text)
{
    static char paths[4][128];
    static int k;
    char *path = paths[k++ & 3];
    FILE *f;
    snprintf(path, 128, "geneva-test-rt-%d-%s", (int)plat_getpid(), name);
    f = fopen(path, "wb");
    if (!f)
        return NULL;
    fputs(text, f);
    fclose(f);
    return path;
}

static void remove_file(const char *path)
{
    if (path)
        remove(path);
}

/* ext_parse_args + the hooks: profiles from FILE, the engine around them */
static int setup(const char *file, engine *e, engine_opts *o, sbuf *err)
{
    static const optdef defs[] = {{"strategy", 's', 1, "S", ""}, {"server-port", 'p', 1, "P", ""},
                                 EXT_OPT, EXT_PROFILE_OPTS, {NULL, 0, 0, NULL, NULL}};
    char aerr[128];
    args_t a;
    const char *argv[6];
    int argc = 0;
    argv[argc++] = "-p";
    argv[argc++] = "1-65535";
    argv[argc++] = "--ext";
    if (file) {
        argv[argc++] = "--ext-profile";
        argv[argc++] = file;
    }
    argv[argc] = NULL;
    ext_reset();
    if (args_parse(&a, argc, (char **)argv, defs, aerr, sizeof(aerr)) < 0)
        return -1;
    if (ext_parse_args(&a, "test") < 0) {
        args_free(&a);
        return -1;
    }
    args_free(&a);
    engine_opts_default(o);
    o->ext = ext_engine_hooks();
    memset(e, 0, sizeof(*e));
    e->o = o;
    e->be = &rbe;
    plat_mutex_init(&e->lock);
    e->st = strategy_parse("\\/", err);
    if (!e->st || engine_workers_init(e, 1, err) < 0)
        return -1;
    return 0;
}

static void teardown(engine *e)
{
    engine_workers_free(e);
    strategy_free(e->st);
    plat_mutex_destroy(&e->lock);
    ext_reset();
}

/* One control command, its answer in out (NULL: none); rctl: ctl is a type */
static int rctl(engine *e, const char *cmd, const char *req_json, sbuf *out, sbuf *err)
{
    json_val *req = req_json ? json_parse(req_json, NULL) : NULL;
    jw w;
    int r;
    sb_init(out);
    jw_init(&w, out);
    jw_obj(&w);
    sb_init(err);
    r = e->o->ext->control(e, cmd, req, &w, err);
    jw_obj_end(&w);
    json_free(req);
    return r;
}

static const char *PROFILES = "[profile one]\n"
                              "filter-tcp = 443\n"
                              "strategy = [TCP:flags:PA]-drop-| \\/\n"
                              "\n"
                              "[profile two]\n"
                              "filter-tcp = 80\n"
                              "strategy = [TCP:flags:PA]-fragment{tcp:34:True:17}-| \\/\n";

TEST(rt_status_lists_profiles)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    const char *f = rt_file("profiles.ini", PROFILES);
    t_current = "profiles: ext_status lists them";
    if (!f || setup(f, &e, &o, &err) < 0) {
        remove_file(f);
        return;
    }
    CHECK_INT(rctl(&e, "ext_status", NULL, &out, &err), 1);
    CHECK(strstr(out.data, "\"profiles\":[") != NULL);
    CHECK(strstr(out.data, "\"profile_n\":1,\"profile\":\"one\"") != NULL);
    CHECK(strstr(out.data, "\"profile_n\":2,\"profile\":\"two\"") != NULL);
    CHECK(strstr(out.data, "\"tcp\":\"443\"") != NULL);
    CHECK(strstr(out.data, "\"tcp\":\"80\"") != NULL);
    CHECK(strstr(out.data, "[TCP:flags:PA]-drop-| \\\\/") != NULL);
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
    remove_file(f);
}

TEST(rt_set_strategy_by_profile)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    const char *f = rt_file("profiles-set.ini", PROFILES);
    t_current = "profiles: set_strategy profile=NAME";
    if (!f || setup(f, &e, &o, &err) < 0) {
        remove_file(f);
        return;
    }
    /* the command's own strategy first: without "profile" the extension is
     * not ours (the engine keeps its path) */
    CHECK_INT(rctl(&e, "set_strategy", "{\"strategy\":\"\\\\/\"}", &out, &err), 0);
    sb_free(&out);
    sb_free(&err);
    /* a profile's */
    CHECK_INT(rctl(&e, "set_strategy",
                  "{\"profile\":\"one\",\"strategy\":\"[TCP:flags:PA]-fragment{tcp:34:True:17}-| \\\\/\"}", &out,
                  &err), 1);
    CHECK(strstr(out.data, "\"profile\":\"one\"") != NULL);
    CHECK(strstr(out.data, "\"profile_n\":1") != NULL);
    CHECK(strstr(out.data, "fragment{tcp:34:True:17}") != NULL);
    sb_free(&out);
    sb_free(&err);
    /* the status shows it */
    rctl(&e, "ext_status", NULL, &out, &err);
    CHECK(strstr(out.data, "\"profile_n\":1,\"profile\":\"one\",\"strategy\":\"[TCP:flags:PA]-fragment") != NULL);
    sb_free(&out);
    sb_free(&err);
    /* a broken strategy: refused, the current stays */
    CHECK_INT(rctl(&e, "set_strategy", "{\"profile\":\"two\",\"strategy\":\"[TCP:flags:S]-nope-| \\\\/\"}", &out,
                  &err), -1);
    CHECK(strstr(err.data, "profile 2 (two):") != NULL);
    sb_free(&out);
    sb_free(&err);
    rctl(&e, "ext_status", NULL, &out, &err);
    CHECK(strstr(out.data, "\"profile\":\"two\",\"strategy\":\"[TCP:flags:PA]-fragment{tcp:34:True:17}") != NULL);
    sb_free(&out);
    sb_free(&err);
    /* no such profile */
    CHECK_INT(rctl(&e, "set_strategy", "{\"profile\":\"nope\",\"strategy\":\"\\\\/\"}", &out, &err), -1);
    CHECK_STR(err.data, "no profile \"nope\"");
    sb_free(&out);
    sb_free(&err);
    /* a profile needs a strategy */
    CHECK_INT(rctl(&e, "set_strategy", "{\"profile\":\"one\"}", &out, &err), -1);
    CHECK_STR(err.data, "set_strategy with \"profile\" needs \"strategy\" or \"strategy_file\"");
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
    remove_file(f);
}

TEST(rt_set_strategy_from_file)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    const char *f = rt_file("profiles-sf.ini", PROFILES);
    const char *s = rt_file("strategy.txt", "[TCP:flags:PA]-drop-| \\/\n");
    t_current = "profiles: set_strategy profile= from strategy_file";
    if (!f || !s || setup(f, &e, &o, &err) < 0) {
        remove_file(f);
        remove_file(s);
        return;
    }
    {
        char req[512];
        snprintf(req, sizeof(req), "{\"profile\":\"two\",\"strategy_file\":\"%s\"}", s);
        CHECK_INT(rctl(&e, "set_strategy", req, &out, &err), 1);
    }
    CHECK(strstr(out.data, "\"profile\":\"two\"") != NULL);
    CHECK(strstr(out.data, "[TCP:flags:PA]-drop-| \\\\/") != NULL);
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
    remove_file(f);
    remove_file(s);
}

TEST(rt_reload_in_place)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    const char *f = rt_file("profiles-reload.ini", PROFILES);
    t_current = "profiles: reload reads the file again";
    if (!f || setup(f, &e, &o, &err) < 0) {
        remove_file(f);
        return;
    }
    /* the file changes: the same two profiles, another strategy of one */
    f = rt_file("profiles-reload.ini", "[profile one]\n"
                                          "filter-tcp = 443\n"
                                          "strategy = [TCP:flags:PA]-fragment{tcp:-1:True}-| \\/\n"
                                          "\n"
                                          "[profile two]\n"
                                          "filter-tcp = 80\n"
                                          "strategy = [TCP:flags:PA]-fragment{tcp:34:True:17}-| \\/\n");
    CHECK_INT(rctl(&e, "reload", "{}", &out, &err), 1);
    CHECK(strstr(out.data, "\"profiles\":2") != NULL);
    sb_free(&out);
    sb_free(&err);
    rctl(&e, "ext_status", NULL, &out, &err);
    CHECK(strstr(out.data, "\"profile\":\"one\",\"strategy\":\"[TCP:flags:PA]-fragment{tcp:-1:True}") != NULL);
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
    remove_file(f);
}

TEST(rt_reload_refuses_a_new_set)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    const char *f = rt_file("profiles-changed.ini", PROFILES);
    t_current = "profiles: reload refuses a set that changed";
    if (!f || setup(f, &e, &o, &err) < 0) {
        remove_file(f);
        return;
    }
    f = rt_file("profiles-changed.ini", "[profile one]\n"
                                           "filter-tcp = 443\n"
                                           "strategy = [TCP:flags:PA]-drop-| \\/\n"
                                           "\n"
                                           "[profile renamed]\n"
                                           "filter-tcp = 80\n"
                                           "strategy = [TCP:flags:PA]-drop-| \\/\n");
    CHECK_INT(rctl(&e, "reload", "{}", &out, &err), -1);
    CHECK_STR(err.data, "the profiles changed (a name or their order): restart to apply");
    sb_free(&out);
    sb_free(&err);
    /* and the current ones are untouched */
    rctl(&e, "ext_status", NULL, &out, &err);
    CHECK(strstr(out.data, "\"profile\":\"two\"") != NULL);
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
    remove_file(f);
}

TEST(rt_reload_refuses_changed_filters)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    const char *f = rt_file("profiles-filters.ini", PROFILES);
    t_current = "profiles: reload refuses changed filters";
    if (!f || setup(f, &e, &o, &err) < 0) {
        remove_file(f);
        return;
    }
    /* the same two profiles, a new port of one: the rules would not follow */
    f = rt_file("profiles-filters.ini", "[profile one]\n"
                                        "filter-tcp = 444\n"
                                        "strategy = [TCP:flags:PA]-drop-| \\/\n"
                                        "\n"
                                        "[profile two]\n"
                                        "filter-tcp = 80\n"
                                        "strategy = [TCP:flags:PA]-fragment{tcp:34:True:17}-| \\/\n");
    CHECK_INT(rctl(&e, "reload", "{}", &out, &err), -1);
    CHECK(strstr(err.data, "its filters changed (ports, L3, L7, mark, SSID or the autolist): restart to apply") != NULL);
    sb_free(&out);
    sb_free(&err);
    /* the current port is still 443 */
    rctl(&e, "ext_status", NULL, &out, &err);
    CHECK(strstr(out.data, "\"tcp\":\"443\"") != NULL);
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
    remove_file(f);
}

TEST(rt_reload_without_profiles)
{
    engine e;
    engine_opts o;
    sbuf out, err;
    t_current = "profiles: reload without --ext-profile is not ours";
    if (setup(NULL, &e, &o, &err) < 0)
        return;
    /* no profile file: the engine's own reload (its --strategy-file) */
    CHECK_INT(rctl(&e, "reload", "{}", &out, &err), 0);
    sb_free(&out);
    sb_free(&err);
    teardown(&e);
}

void suite_profile_runtime(void)
{
    RUN(rt_status_lists_profiles);
    RUN(rt_set_strategy_by_profile);
    RUN(rt_set_strategy_from_file);
    RUN(rt_reload_in_place);
    RUN(rt_reload_refuses_a_new_set);
    RUN(rt_reload_refuses_changed_filters);
    RUN(rt_reload_without_profiles);
}

#else
void suite_profile_runtime(void) {}
#endif
