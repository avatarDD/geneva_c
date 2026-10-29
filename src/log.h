/*
 * Logging and the telemetry event stream.
 *
 * Events are JSON Lines: one object per line, always carrying "ts" (ms since
 * the epoch) and "ev" (event type). They go to the configured sink (stdout,
 * a file, or nowhere) and to an optional tap that the control socket uses to
 * stream events to subscribed clients. The schema is documented in
 * docs/PROTOCOL.md.
 */
#ifndef GENEVA_LOG_H
#define GENEVA_LOG_H

#include <stddef.h>

#include "json.h"
#include "util.h"

#define GENEVA_PROTO_VERSION 1

typedef enum {
    LOG_ERROR = 0,
    LOG_WARN = 1,
    LOG_INFO = 2,
    LOG_DEBUG = 3,
    LOG_TRACE = 4, /* per-packet detail */
} log_level;

typedef enum { LOG_FMT_TEXT, LOG_FMT_JSON } log_format;

/* Must run before any thread is started. */
void log_init(void);
void log_set_level(log_level lvl);
log_level log_get_level(void);
int log_parse_level(const char *s, log_level *out);
const char *log_level_name(log_level lvl);
void log_set_format(log_format f);
/* Optional log file in addition to stderr (text mode). */
int log_open_file(const char *path);
/* Silence stderr output (used when a controller reads only the event stream). */
void log_set_quiet(int quiet);

#define log_enabled(lvl) ((lvl) <= log_get_level())

void log_msg(log_level lvl, const char *mod, const char *fmt, ...) PRINTF_LIKE(3, 4);

#define LOGE(mod, ...) log_msg(LOG_ERROR, mod, __VA_ARGS__)
#define LOGW(mod, ...) log_msg(LOG_WARN, mod, __VA_ARGS__)
#define LOGI(mod, ...) do { if (log_enabled(LOG_INFO)) log_msg(LOG_INFO, mod, __VA_ARGS__); } while (0)
#define LOGD(mod, ...) do { if (log_enabled(LOG_DEBUG)) log_msg(LOG_DEBUG, mod, __VA_ARGS__); } while (0)
#define LOGT(mod, ...) do { if (log_enabled(LOG_TRACE)) log_msg(LOG_TRACE, mod, __VA_ARGS__); } while (0)

/* ---- events -------------------------------------------------------------- */

/* spec: "-" or "stdout", "stderr", "none", or a file path (appended). */
int ev_open(const char *spec);
void ev_close(void);
/* True when somebody would receive an event (sink or tap). */
int ev_enabled(void);

typedef void (*ev_tap_fn)(const char *line, size_t len, void *ctx);
void ev_set_tap(ev_tap_fn fn, void *ctx);

typedef struct {
    sbuf sb;
    jw w;
} ev_t;

/* Starts {"ts":..,"ev":"name" ; add fields with jw_* on e->w, then ev_emit. */
void ev_begin(ev_t *e, const char *name);
void ev_emit(ev_t *e);
/* Drops an event without sending it. */
void ev_discard(ev_t *e);

#endif
