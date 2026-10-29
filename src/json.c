#include "json.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- writer -------------------------------------------------------------- */

void jw_init(jw *w, sbuf *sb)
{
    memset(w, 0, sizeof(*w));
    w->sb = sb;
}

static void jw_pre(jw *w)
{
    if (w->after_key) {
        w->after_key = 0;
        return;
    }
    if (w->depth > 0) {
        if (w->need_comma[w->depth - 1])
            sb_putc(w->sb, ',');
        w->need_comma[w->depth - 1] = 1;
    }
}

static void jw_open(jw *w, char c)
{
    jw_pre(w);
    sb_putc(w->sb, c);
    if (w->depth < JW_MAX_DEPTH)
        w->need_comma[w->depth] = 0;
    w->depth++;
}

static void jw_close(jw *w, char c)
{
    if (w->depth > 0)
        w->depth--;
    sb_putc(w->sb, c);
}

void jw_obj(jw *w) { jw_open(w, '{'); }
void jw_obj_end(jw *w) { jw_close(w, '}'); }
void jw_arr(jw *w) { jw_open(w, '['); }
void jw_arr_end(jw *w) { jw_close(w, ']'); }

void json_escape(sbuf *out, const char *s, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    sb_putc(out, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"': sb_puts(out, "\\\""); break;
        case '\\': sb_puts(out, "\\\\"); break;
        case '\n': sb_puts(out, "\\n"); break;
        case '\r': sb_puts(out, "\\r"); break;
        case '\t': sb_puts(out, "\\t"); break;
        default:
            if (c < 0x20 || c == 0x7f) {
                char e[6] = {'\\', 'u', '0', '0', hex[c >> 4], hex[c & 15]};
                sb_append(out, e, 6);
            } else {
                sb_putc(out, (char)c);
            }
        }
    }
    sb_putc(out, '"');
}

void jw_key(jw *w, const char *k)
{
    jw_pre(w);
    json_escape(w->sb, k, strlen(k));
    sb_putc(w->sb, ':');
    w->after_key = 1;
}

void jw_strn(jw *w, const char *s, size_t n)
{
    jw_pre(w);
    json_escape(w->sb, s, n);
}

void jw_str(jw *w, const char *s)
{
    if (!s) {
        jw_null(w);
        return;
    }
    jw_strn(w, s, strlen(s));
}

void jw_int(jw *w, int64_t v)
{
    jw_pre(w);
    sb_printf(w->sb, "%lld", (long long)v);
}

void jw_uint(jw *w, uint64_t v)
{
    jw_pre(w);
    sb_printf(w->sb, "%llu", (unsigned long long)v);
}

void jw_dbl(jw *w, double v)
{
    jw_pre(w);
    if (isnan(v) || isinf(v)) {
        sb_puts(w->sb, "null");
        return;
    }
    if (v == (double)(long long)v && fabs(v) < 1e15)
        sb_printf(w->sb, "%lld", (long long)v);
    else
        sb_printf(w->sb, "%.6g", v);
}

void jw_bool(jw *w, int v)
{
    jw_pre(w);
    sb_puts(w->sb, v ? "true" : "false");
}

void jw_null(jw *w)
{
    jw_pre(w);
    sb_puts(w->sb, "null");
}

void jw_raw(jw *w, const char *json)
{
    jw_pre(w);
    sb_puts(w->sb, json);
}

void jw_kstr(jw *w, const char *k, const char *s) { jw_key(w, k); jw_str(w, s); }
void jw_kint(jw *w, const char *k, int64_t v) { jw_key(w, k); jw_int(w, v); }
void jw_kuint(jw *w, const char *k, uint64_t v) { jw_key(w, k); jw_uint(w, v); }
void jw_kdbl(jw *w, const char *k, double v) { jw_key(w, k); jw_dbl(w, v); }
void jw_kbool(jw *w, const char *k, int v) { jw_key(w, k); jw_bool(w, v); }

/* ---- parser -------------------------------------------------------------- */

typedef struct {
    const char *p;
    const char *err;
    int depth;
} jp;

static void skip_ws(jp *s)
{
    while (*s->p == ' ' || *s->p == '\t' || *s->p == '\n' || *s->p == '\r')
        s->p++;
}

static json_val *jv_new(json_type t)
{
    json_val *v = xcalloc(1, sizeof(*v));
    v->type = t;
    return v;
}

static void put_utf8(sbuf *b, unsigned cp)
{
    char o[4];
    if (cp < 0x80) {
        o[0] = (char)cp;
        sb_append(b, o, 1);
    } else if (cp < 0x800) {
        o[0] = (char)(0xC0 | (cp >> 6));
        o[1] = (char)(0x80 | (cp & 0x3F));
        sb_append(b, o, 2);
    } else if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12));
        o[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[2] = (char)(0x80 | (cp & 0x3F));
        sb_append(b, o, 3);
    } else {
        o[0] = (char)(0xF0 | (cp >> 18));
        o[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        o[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        o[3] = (char)(0x80 | (cp & 0x3F));
        sb_append(b, o, 4);
    }
}

static int hex4(const char *p, unsigned *out)
{
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (unsigned)(c - 'A' + 10);
        else
            return -1;
    }
    *out = v;
    return 0;
}

static char *parse_string(jp *s)
{
    sbuf b;
    if (*s->p != '"') {
        s->err = "expected string";
        return NULL;
    }
    s->p++;
    sb_init(&b);
    while (*s->p && *s->p != '"') {
        if ((unsigned char)*s->p < 0x20) {
            s->err = "control character in string";
            sb_free(&b);
            return NULL;
        }
        if (*s->p != '\\') {
            sb_putc(&b, *s->p++);
            continue;
        }
        s->p++;
        switch (*s->p) {
        case '"': sb_putc(&b, '"'); break;
        case '\\': sb_putc(&b, '\\'); break;
        case '/': sb_putc(&b, '/'); break;
        case 'b': sb_putc(&b, '\b'); break;
        case 'f': sb_putc(&b, '\f'); break;
        case 'n': sb_putc(&b, '\n'); break;
        case 'r': sb_putc(&b, '\r'); break;
        case 't': sb_putc(&b, '\t'); break;
        case 'u': {
            unsigned cp, lo;
            if (hex4(s->p + 1, &cp) < 0) {
                s->err = "bad \\u escape";
                sb_free(&b);
                return NULL;
            }
            s->p += 4;
            if (cp >= 0xD800 && cp < 0xDC00 && s->p[1] == '\\' && s->p[2] == 'u' &&
                hex4(s->p + 3, &lo) == 0 && lo >= 0xDC00 && lo < 0xE000) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                s->p += 6;
            }
            put_utf8(&b, cp);
            break;
        }
        default:
            s->err = "bad escape";
            sb_free(&b);
            return NULL;
        }
        s->p++;
    }
    if (*s->p != '"') {
        s->err = "unterminated string";
        sb_free(&b);
        return NULL;
    }
    s->p++;
    return sb_take(&b);
}

static json_val *parse_value(jp *s);

static json_val *parse_container(jp *s, int is_obj)
{
    json_val *v = jv_new(is_obj ? JSON_OBJ : JSON_ARR);
    size_t cap = 0;
    char close = is_obj ? '}' : ']';
    s->p++;
    skip_ws(s);
    if (*s->p == close) {
        s->p++;
        return v;
    }
    for (;;) {
        char *key = NULL;
        json_val *item;
        skip_ws(s);
        if (is_obj) {
            key = parse_string(s);
            if (!key)
                goto fail;
            skip_ws(s);
            if (*s->p != ':') {
                free(key);
                s->err = "expected ':'";
                goto fail;
            }
            s->p++;
        }
        item = parse_value(s);
        if (!item) {
            free(key);
            goto fail;
        }
        if (v->n == cap) {
            cap = cap ? cap * 2 : 4;
            v->items = xrealloc(v->items, cap * sizeof(*v->items));
            if (is_obj)
                v->keys = xrealloc(v->keys, cap * sizeof(*v->keys));
        }
        v->items[v->n] = item;
        if (is_obj)
            v->keys[v->n] = key;
        v->n++;
        skip_ws(s);
        if (*s->p == ',') {
            s->p++;
            continue;
        }
        if (*s->p == close) {
            s->p++;
            return v;
        }
        s->err = is_obj ? "expected ',' or '}'" : "expected ',' or ']'";
        goto fail;
    }
fail:
    json_free(v);
    return NULL;
}

static json_val *parse_value(jp *s)
{
    json_val *v;
    skip_ws(s);
    if (++s->depth > 64) {
        s->err = "nesting too deep";
        return NULL;
    }
    switch (*s->p) {
    case '{':
        v = parse_container(s, 1);
        break;
    case '[':
        v = parse_container(s, 0);
        break;
    case '"': {
        char *str = parse_string(s);
        if (!str)
            return NULL;
        v = jv_new(JSON_STR);
        v->str = str;
        break;
    }
    case 't':
        if (strncmp(s->p, "true", 4) == 0) {
            s->p += 4;
            v = jv_new(JSON_BOOL);
            v->boolean = 1;
            break;
        }
        s->err = "bad literal";
        return NULL;
    case 'f':
        if (strncmp(s->p, "false", 5) == 0) {
            s->p += 5;
            v = jv_new(JSON_BOOL);
            break;
        }
        s->err = "bad literal";
        return NULL;
    case 'n':
        if (strncmp(s->p, "null", 4) == 0) {
            s->p += 4;
            v = jv_new(JSON_NULL);
            break;
        }
        s->err = "bad literal";
        return NULL;
    default: {
        char *end;
        double d;
        if (!(*s->p == '-' || (*s->p >= '0' && *s->p <= '9'))) {
            s->err = "unexpected character";
            return NULL;
        }
        d = strtod(s->p, &end);
        if (end == s->p) {
            s->err = "bad number";
            return NULL;
        }
        s->p = end;
        v = jv_new(JSON_NUM);
        v->num = d;
        break;
    }
    }
    s->depth--;
    return v;
}

json_val *json_parse(const char *text, const char **err)
{
    jp s = {text, NULL, 0};
    json_val *v = parse_value(&s);
    if (v) {
        skip_ws(&s);
        if (*s.p) {
            json_free(v);
            v = NULL;
            s.err = "trailing characters";
        }
    }
    if (!v && err)
        *err = s.err ? s.err : "parse error";
    return v;
}

void json_free(json_val *v)
{
    if (!v)
        return;
    for (size_t i = 0; i < v->n; i++) {
        json_free(v->items[i]);
        if (v->keys)
            free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->str);
    free(v);
}

const json_val *json_get(const json_val *obj, const char *key)
{
    if (!obj || obj->type != JSON_OBJ)
        return NULL;
    for (size_t i = 0; i < obj->n; i++)
        if (strcmp(obj->keys[i], key) == 0)
            return obj->items[i];
    return NULL;
}

const char *json_get_str(const json_val *obj, const char *key, const char *def)
{
    const json_val *v = json_get(obj, key);
    return v && v->type == JSON_STR ? v->str : def;
}

int64_t json_get_int(const json_val *obj, const char *key, int64_t def)
{
    const json_val *v = json_get(obj, key);
    return v && v->type == JSON_NUM ? (int64_t)v->num : def;
}

double json_get_num(const json_val *obj, const char *key, double def)
{
    const json_val *v = json_get(obj, key);
    return v && v->type == JSON_NUM ? v->num : def;
}

int json_get_bool(const json_val *obj, const char *key, int def)
{
    const json_val *v = json_get(obj, key);
    return v && v->type == JSON_BOOL ? v->boolean : def;
}
