#include "cfgfile.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

static int is_blank(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

/* $NAME or ${NAME} at text[*i] (just after the '$'): appends the value */
static int var(const char *t, size_t len, size_t *i, sbuf *w, sbuf *err)
{
    char name[128];
    size_t n = 0, j = *i;
    int brace = j < len && t[j] == '{';
    const char *v;
    if (j < len && (t[j] == '(')) {
        sb_puts(err, "$( ) runs a command: not allowed");
        return -1;
    }
    if (brace)
        j++;
    while (j < len && (isalnum((unsigned char)t[j]) || t[j] == '_') && n < sizeof(name) - 1)
        name[n++] = t[j++];
    name[n] = 0;
    if (j < len && (isalnum((unsigned char)t[j]) || t[j] == '_')) {
        sb_puts(err, "variable name too long");
        return -1;
    }
    if (brace) {
        if (j >= len || t[j] != '}' || !n) {
            sb_puts(err, "bad ${NAME}");
            return -1;
        }
        j++;
    }
    if (!n) {
        sb_putc(w, '$'); /* a lone $ */
        return 0;
    }
    v = getenv(name);
    if (v)
        sb_puts(w, v);
    *i = j;
    return 0;
}

int xcfg_split(const char *t, size_t len, char ***words, sbuf *err)
{
    char **v = NULL;
    size_t n = 0, cap = 0, i = 0;
    sbuf w;
    sb_init(&w);
    *words = NULL;
    for (;;) {
        int have = 0;
        while (i < len && is_blank(t[i]))
            i++;
        if (i >= len)
            break;
        if (t[i] == '#') {
            while (i < len && t[i] != '\n')
                i++;
            continue;
        }
        sb_reset(&w);
        while (i < len && !is_blank(t[i])) {
            char c = t[i];
            have = 1;
            if (c == '\'') {
                size_t e = i + 1;
                while (e < len && t[e] != '\'')
                    e++;
                if (e >= len) {
                    sb_puts(err, "unterminated '");
                    goto fail;
                }
                sb_append(&w, t + i + 1, e - i - 1);
                i = e + 1;
            } else if (c == '"') {
                i++;
                for (;;) {
                    if (i >= len) {
                        sb_puts(err, "unterminated \"");
                        goto fail;
                    }
                    c = t[i];
                    if (c == '"') {
                        i++;
                        break;
                    }
                    if (c == '`') {
                        sb_puts(err, "`...` runs a command: not allowed");
                        goto fail;
                    }
                    if (c == '\\' && i + 1 < len && strchr("\"\\$`\n", t[i + 1])) {
                        if (t[i + 1] != '\n')
                            sb_putc(&w, t[i + 1]);
                        i += 2;
                    } else if (c == '$') {
                        i++;
                        if (var(t, len, &i, &w, err) < 0)
                            goto fail;
                    } else {
                        sb_putc(&w, c);
                        i++;
                    }
                }
            } else if (c == '\\') {
                if (i + 1 >= len) {
                    sb_puts(err, "a backslash at the end");
                    goto fail;
                }
                if (t[i + 1] != '\n')
                    sb_putc(&w, t[i + 1]);
                i += 2;
            } else if (c == '$') {
                i++;
                if (var(t, len, &i, &w, err) < 0)
                    goto fail;
            } else if (c == '`') {
                sb_puts(err, "`...` runs a command: not allowed");
                goto fail;
            } else if (!c) {
                sb_puts(err, "a NUL byte");
                goto fail;
            } else {
                sb_putc(&w, c);
                i++;
            }
        }
        if (!have)
            continue;
        if (n + 2 > cap) {
            cap = cap ? cap * 2 : 16;
            v = realloc(v, cap * sizeof(*v));
            if (!v)
                abort();
        }
        v[n++] = xstrdup(w.data ? w.data : "");
        v[n] = NULL;
    }
    sb_free(&w);
    if (!v)
        v = xcalloc(1, sizeof(*v));
    *words = v;
    return (int)n;
fail:
    sb_free(&w);
    if (v)
        v[n] = NULL;
    xcfg_free(v);
    return -1;
}

void xcfg_free(char **words)
{
    if (!words)
        return;
    for (char **p = words; *p; p++)
        free(*p);
    free(words);
}

int xcfg_expand(int *argc, char ***argv, sbuf *err)
{
    const char *path;
    char *text, **words, **nv;
    size_t len;
    int n, ext = 0;
    if (*argc < 1 || ((*argv)[0][0] != '@' && (*argv)[0][0] != '$'))
        return 0;
    path = (*argv)[0] + 1;
    if (!*path) {
        sb_puts(err, "@FILE: no file name");
        return -1;
    }
    text = read_file(path, &len);
    if (!text) {
        sb_printf(err, "cannot read %s", path);
        return -1;
    }
    if (len > XCFG_MAX) {
        free(text);
        sb_printf(err, "%s: longer than %d bytes", path, XCFG_MAX);
        return -1;
    }
    n = xcfg_split(text, len, &words, err);
    free(text);
    if (n < 0) {
        char *m = sb_take(err);
        sb_printf(err, "%s: %s", path, m);
        free(m);
        return -1;
    }
    nv = xcalloc((size_t)n + (size_t)*argc + 1, sizeof(*nv));
    memcpy(nv, words, (size_t)n * sizeof(*nv));
    free(words); /* the strings live on in nv, for the process */
    memcpy(nv + n, *argv + 1, (size_t)(*argc - 1) * sizeof(*nv));
    n += *argc - 1;
    for (int i = 0; i < n; i++)
        if (!strcmp(nv[i], "--ext"))
            ext = 1;
    if (!ext) {
        for (int i = 0; i < n - (*argc - 1); i++)
            free(nv[i]);
        free(nv);
        sb_printf(err, "options from %s need --ext", path);
        return -1;
    }
    *argc = n;
    *argv = nv;
    return 1;
}
