/* Minimal JSON writer and DOM parser (no dependencies, UTF-8 pass-through). */
#ifndef GENEVA_JSON_H
#define GENEVA_JSON_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

/* ---- writer -------------------------------------------------------------- */

#define JW_MAX_DEPTH 32

typedef struct {
    sbuf *sb;
    int depth;
    uint8_t need_comma[JW_MAX_DEPTH];
    uint8_t after_key;
} jw;

void jw_init(jw *w, sbuf *sb);
void jw_obj(jw *w);
void jw_obj_end(jw *w);
void jw_arr(jw *w);
void jw_arr_end(jw *w);
void jw_key(jw *w, const char *k);
void jw_str(jw *w, const char *s);
void jw_strn(jw *w, const char *s, size_t n);
void jw_int(jw *w, int64_t v);
void jw_uint(jw *w, uint64_t v);
void jw_dbl(jw *w, double v);
void jw_bool(jw *w, int v);
void jw_null(jw *w);
/* Inserts pre-serialized JSON as one value. */
void jw_raw(jw *w, const char *json);

void jw_kstr(jw *w, const char *k, const char *s);
void jw_kint(jw *w, const char *k, int64_t v);
void jw_kuint(jw *w, const char *k, uint64_t v);
void jw_kdbl(jw *w, const char *k, double v);
void jw_kbool(jw *w, const char *k, int v);

/* Appends s as a quoted, escaped JSON string. */
void json_escape(sbuf *out, const char *s, size_t n);

/* ---- parser -------------------------------------------------------------- */

typedef enum { JSON_NULL, JSON_BOOL, JSON_NUM, JSON_STR, JSON_ARR, JSON_OBJ } json_type;

typedef struct json_val json_val;
struct json_val {
    json_type type;
    int boolean;
    double num;
    char *str;
    size_t n;         /* number of items/members */
    json_val **items; /* array items or object values */
    char **keys;      /* object keys (NULL for arrays) */
};

/* Returns NULL on error and sets *err to a static message. */
json_val *json_parse(const char *text, const char **err);
void json_free(json_val *v);
const json_val *json_get(const json_val *obj, const char *key);
const char *json_get_str(const json_val *obj, const char *key, const char *def);
int64_t json_get_int(const json_val *obj, const char *key, int64_t def);
double json_get_num(const json_val *obj, const char *key, double def);
int json_get_bool(const json_val *obj, const char *key, int def);

#endif
