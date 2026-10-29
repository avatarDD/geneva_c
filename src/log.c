#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "plat.h"

static log_level g_level = LOG_INFO;
static log_format g_format = LOG_FMT_TEXT;
static int g_quiet;
static FILE *g_logfile;

static FILE *g_sink;
static int g_sink_owned;
static ev_tap_fn g_tap;
static void *g_tap_ctx;

static plat_mutex_t g_mu;
static int g_mu_ready;

void log_init(void)
{
    if (!g_mu_ready) {
        plat_mutex_init(&g_mu);
        g_mu_ready = 1;
    }
}

static void lock(void)
{
    /* log_init() runs in main() before any thread starts; the lazy call only
     * covers unit tests and early errors. */
    log_init();
    plat_mutex_lock(&g_mu);
}

static void unlock(void) { plat_mutex_unlock(&g_mu); }

static const char *level_names[] = {"error", "warn", "info", "debug", "trace"};

void log_set_level(log_level lvl) { g_level = lvl; }
log_level log_get_level(void) { return g_level; }
const char *log_level_name(log_level lvl) { return level_names[lvl]; }
void log_set_format(log_format f) { g_format = f; }
void log_set_quiet(int quiet) { g_quiet = quiet; }

int log_parse_level(const char *s, log_level *out)
{
    for (int i = 0; i < (int)ARRAY_LEN(level_names); i++) {
        if (str_ieq(s, level_names[i])) {
            *out = (log_level)i;
            return 0;
        }
    }
    if (str_ieq(s, "warning")) {
        *out = LOG_WARN;
        return 0;
    }
    if (str_ieq(s, "critical")) {
        *out = LOG_ERROR;
        return 0;
    }
    return -1;
}

int log_open_file(const char *path)
{
    FILE *f = fopen(path, "a");
    if (!f)
        return -1;
    if (g_logfile)
        fclose(g_logfile);
    g_logfile = f;
    return 0;
}

static void fmt_time(char *buf, size_t n, uint64_t ms)
{
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    snprintf(buf, n, "%04d-%02d-%02d %02d:%02d:%02d.%03u", tm.tm_year + 1900, tm.tm_mon + 1,
             tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, (unsigned)(ms % 1000));
}

void log_msg(log_level lvl, const char *mod, const char *fmt, ...)
{
    sbuf msg;
    va_list ap;
    uint64_t now;
    if (lvl > g_level)
        return;
    now = plat_wall_ms();
    sb_init(&msg);
    va_start(ap, fmt);
    sb_vprintf(&msg, fmt, ap);
    va_end(ap);

    if (g_format == LOG_FMT_TEXT || g_logfile) {
        char ts[40];
        fmt_time(ts, sizeof(ts), now);
        lock();
        if (g_format == LOG_FMT_TEXT && !g_quiet)
            fprintf(stderr, "%s %-5s %s: %s\n", ts, level_names[lvl], mod, msg.data);
        if (g_logfile) {
            fprintf(g_logfile, "%s %-5s %s: %s\n", ts, level_names[lvl], mod, msg.data);
            fflush(g_logfile);
        }
        unlock();
    }
    /* In JSON mode logs are part of the event stream; in text mode they are
     * still offered to control-socket subscribers through the tap. */
    if (g_format == LOG_FMT_JSON || g_tap) {
        ev_t e;
        ev_begin(&e, "log");
        jw_kstr(&e.w, "level", level_names[lvl]);
        jw_kstr(&e.w, "mod", mod);
        jw_kstr(&e.w, "msg", msg.data);
        if (g_format == LOG_FMT_JSON) {
            ev_emit(&e);
        } else {
            jw_obj_end(&e.w);
            sb_putc(&e.sb, '\n');
            lock();
            if (g_tap)
                g_tap(e.sb.data, e.sb.len, g_tap_ctx);
            unlock();
            sb_free(&e.sb);
        }
    }
    sb_free(&msg);
}

/* ---- events -------------------------------------------------------------- */

int ev_open(const char *spec)
{
    ev_close();
    if (!spec || str_ieq(spec, "none"))
        return 0;
    if (strcmp(spec, "-") == 0 || str_ieq(spec, "stdout")) {
        g_sink = stdout;
    } else if (str_ieq(spec, "stderr")) {
        g_sink = stderr;
    } else {
        g_sink = fopen(spec, "a");
        if (!g_sink)
            return -1;
        g_sink_owned = 1;
    }
    return 0;
}

void ev_close(void)
{
    if (g_sink && g_sink_owned)
        fclose(g_sink);
    g_sink = NULL;
    g_sink_owned = 0;
}

int ev_enabled(void) { return g_sink != NULL || g_tap != NULL; }

void ev_set_tap(ev_tap_fn fn, void *ctx)
{
    lock();
    g_tap = fn;
    g_tap_ctx = ctx;
    unlock();
}

void ev_begin(ev_t *e, const char *name)
{
    sb_init(&e->sb);
    jw_init(&e->w, &e->sb);
    jw_obj(&e->w);
    jw_kuint(&e->w, "ts", plat_wall_ms());
    jw_kstr(&e->w, "ev", name);
}

void ev_emit(ev_t *e)
{
    jw_obj_end(&e->w);
    sb_putc(&e->sb, '\n');
    lock();
    if (g_sink) {
        fwrite(e->sb.data, 1, e->sb.len, g_sink);
        fflush(g_sink);
    }
    if (g_tap)
        g_tap(e->sb.data, e->sb.len, g_tap_ctx);
    unlock();
    sb_free(&e->sb);
}

void ev_discard(ev_t *e) { sb_free(&e->sb); }
