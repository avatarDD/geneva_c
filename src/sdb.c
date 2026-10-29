#include "sdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json.h"
#include "log.h"
#include "plat.h"

struct sdb {
    char *path;
    FILE *app; /* append handle, opened on the first write */
    sdb_rec *v;
    size_t n, cap;
    size_t *idx; /* open addressing: record index + 1, 0 = empty */
    size_t idx_cap;
    size_t lines; /* lines in the file */
};

/* ---- records ------------------------------------------------------------- */

void sdb_rec_free(sdb_rec *r)
{
    free(r->s);
    free(r->t);
    r->s = r->t = NULL;
}

void sdb_rec_json(const sdb_rec *r, sbuf *out)
{
    jw w;
    jw_init(&w, out);
    jw_obj(&w);
    jw_kstr(&w, "s", r->s);
    jw_kstr(&w, "t", r->t);
    jw_kuint(&w, "runs", r->runs);
    jw_kuint(&w, "ok", r->ok);
    jw_kdbl(&w, "fit_sum", r->fit_sum);
    jw_kdbl(&w, "fit_best", r->fit_best);
    jw_kuint(&w, "first", r->first);
    jw_kuint(&w, "last", r->last);
    jw_kuint(&w, "last_ok", r->last_ok);
    jw_obj_end(&w);
}

int sdb_rec_parse(const char *line, sdb_rec *r)
{
    const char *perr;
    json_val *v = json_parse(line, &perr);
    const char *s, *t;
    int64_t runs, ok;
    memset(r, 0, sizeof(*r));
    if (!v || v->type != JSON_OBJ) {
        json_free(v);
        return -1;
    }
    s = json_get_str(v, "s", NULL);
    t = json_get_str(v, "t", "");
    runs = json_get_int(v, "runs", 0);
    ok = json_get_int(v, "ok", 0);
    if (!s || !*s || runs < 0 || ok < 0 || ok > runs) {
        json_free(v);
        return -1;
    }
    r->s = xstrdup(s);
    r->t = xstrdup(t);
    r->runs = (uint64_t)runs;
    r->ok = (uint64_t)ok;
    r->fit_sum = json_get_num(v, "fit_sum", 0);
    r->fit_best = json_get_num(v, "fit_best", 0);
    r->first = (uint64_t)json_get_int(v, "first", 0);
    r->last = (uint64_t)json_get_int(v, "last", 0);
    r->last_ok = (uint64_t)json_get_int(v, "last_ok", 0);
    json_free(v);
    return 0;
}

/* ---- index --------------------------------------------------------------- */

static uint64_t key_hash(const char *s, const char *t)
{
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++)
        h = (h ^ (uint8_t)*s) * 1099511628211ull;
    h = (h ^ 1) * 1099511628211ull;
    for (; *t; t++)
        h = (h ^ (uint8_t)*t) * 1099511628211ull;
    return h;
}

static void index_rebuild(sdb *db)
{
    free(db->idx);
    db->idx_cap = 64;
    while (db->idx_cap < db->n * 2 + 2)
        db->idx_cap *= 2;
    db->idx = xcalloc(db->idx_cap, sizeof(*db->idx));
    for (size_t i = 0; i < db->n; i++) {
        size_t h = (size_t)key_hash(db->v[i].s, db->v[i].t) & (db->idx_cap - 1);
        while (db->idx[h])
            h = (h + 1) & (db->idx_cap - 1);
        db->idx[h] = i + 1;
    }
}

static long index_find(const sdb *db, const char *s, const char *t)
{
    size_t h;
    if (!db->idx_cap)
        return -1;
    h = (size_t)key_hash(s, t) & (db->idx_cap - 1);
    while (db->idx[h]) {
        const sdb_rec *r = &db->v[db->idx[h] - 1];
        if (!strcmp(r->s, s) && !strcmp(r->t, t))
            return (long)(db->idx[h] - 1);
        h = (h + 1) & (db->idx_cap - 1);
    }
    return -1;
}

static void merge_into(sdb_rec *dst, const sdb_rec *src)
{
    if (!dst->runs || (src->runs && src->fit_best > dst->fit_best))
        dst->fit_best = src->fit_best;
    dst->runs += src->runs;
    dst->ok += src->ok;
    dst->fit_sum += src->fit_sum;
    if (src->first && (!dst->first || src->first < dst->first))
        dst->first = src->first;
    if (src->last > dst->last)
        dst->last = src->last;
    if (src->last_ok > dst->last_ok)
        dst->last_ok = src->last_ok;
}

/* Merges r into memory (taking its strings when it is new). */
static void absorb(sdb *db, sdb_rec *r)
{
    long i = index_find(db, r->s, r->t);
    if (i >= 0) {
        merge_into(&db->v[i], r);
        sdb_rec_free(r);
        return;
    }
    if (db->n == db->cap) {
        db->cap = db->cap ? db->cap * 2 : 64;
        db->v = xrealloc(db->v, db->cap * sizeof(*db->v));
    }
    db->v[db->n++] = *r;
    if (db->n * 2 + 2 > db->idx_cap) {
        index_rebuild(db);
    } else {
        size_t h = (size_t)key_hash(r->s, r->t) & (db->idx_cap - 1);
        while (db->idx[h])
            h = (h + 1) & (db->idx_cap - 1);
        db->idx[h] = db->n;
    }
}

/* ---- file ---------------------------------------------------------------- */

sdb *sdb_open(const char *path, sbuf *err)
{
    sdb *db = xcalloc(1, sizeof(*db));
    size_t len, bad = 0;
    char *text, *line, *next;
    db->path = xstrdup(path);
    index_rebuild(db);
    text = read_file(path, &len);
    if (!text) {
        FILE *f = fopen(path, "ab"); /* a new database: check that it can be created */
        if (!f) {
            sb_printf(err, "cannot open the strategy database %s", path);
            sdb_close(db);
            return NULL;
        }
        fclose(f);
        return db;
    }
    for (line = text; line && *line; line = next) {
        sdb_rec r;
        next = strchr(line, '\n');
        if (next)
            *next++ = 0;
        if (!*line || *line == '\r')
            continue;
        db->lines++;
        if (sdb_rec_parse(line, &r) < 0) {
            bad++;
            continue;
        }
        absorb(db, &r);
    }
    free(text);
    if (bad)
        LOGW("db", "%s: skipped %zu malformed line(s)", path, bad);
    return db;
}

static int append_line(sdb *db, const sdb_rec *r)
{
    sbuf s;
    int rc;
    if (!db->app) {
        db->app = fopen(db->path, "ab");
        if (!db->app) {
            LOGE("db", "cannot write %s", db->path);
            return -1;
        }
    }
    sb_init(&s);
    sdb_rec_json(r, &s);
    sb_putc(&s, '\n');
    rc = fwrite(s.data, 1, s.len, db->app) == s.len && fflush(db->app) == 0 ? 0 : -1;
    sb_free(&s);
    if (rc < 0)
        LOGE("db", "cannot write %s", db->path);
    else
        db->lines++;
    return rc;
}

int sdb_merge(sdb *db, const sdb_rec *r)
{
    sdb_rec c = *r;
    if (append_line(db, r) < 0)
        return -1;
    c.s = xstrdup(r->s);
    c.t = xstrdup(r->t ? r->t : "");
    absorb(db, &c);
    return 0;
}

int sdb_add(sdb *db, const char *strategy, const char *target, double fitness, int ok)
{
    uint64_t now = plat_wall_ms();
    sdb_rec r = {(char *)strategy, (char *)(target ? target : ""), 1, ok ? 1 : 0, fitness, fitness,
                 now, now, ok ? now : 0};
    return sdb_merge(db, &r);
}

static int rewrite(sdb *db)
{
    sbuf s;
    int rc;
    sb_init(&s);
    for (size_t i = 0; i < db->n; i++) {
        sdb_rec_json(&db->v[i], &s);
        sb_putc(&s, '\n');
    }
    if (db->app) {
        fclose(db->app);
        db->app = NULL;
    }
    rc = plat_write_atomic(db->path, s.data ? s.data : "", s.len);
    if (rc == 0)
        db->lines = db->n;
    else
        LOGE("db", "cannot rewrite %s", db->path);
    sb_free(&s);
    return rc;
}

int sdb_compact(sdb *db) { return rewrite(db); }

void sdb_close(sdb *db)
{
    if (!db)
        return;
    if (db->lines > 1000 && db->lines > db->n * 4)
        rewrite(db);
    if (db->app)
        fclose(db->app);
    for (size_t i = 0; i < db->n; i++)
        sdb_rec_free(&db->v[i]);
    free(db->v);
    free(db->idx);
    free(db->path);
    free(db);
}

/* ---- queries ------------------------------------------------------------- */

size_t sdb_count(const sdb *db) { return db->n; }
const sdb_rec *sdb_get(const sdb *db, size_t i) { return i < db->n ? &db->v[i] : NULL; }

const sdb_rec *sdb_find(const sdb *db, const char *strategy, const char *target)
{
    long i = index_find(db, strategy, target ? target : "");
    return i >= 0 ? &db->v[i] : NULL;
}

static int rank_cmp(const void *pa, const void *pb)
{
    const sdb_rec *a = *(const sdb_rec *const *)pa, *b = *(const sdb_rec *const *)pb;
    double ra = a->runs ? (double)a->ok / (double)a->runs : 0;
    double rb = b->runs ? (double)b->ok / (double)b->runs : 0;
    double fa = a->runs ? a->fit_sum / (double)a->runs : 0;
    double fb = b->runs ? b->fit_sum / (double)b->runs : 0;
    if (ra != rb)
        return ra > rb ? -1 : 1;
    if (fa != fb)
        return fa > fb ? -1 : 1;
    if (a->runs != b->runs)
        return a->runs > b->runs ? -1 : 1;
    return strcmp(a->s, b->s);
}

size_t sdb_top(const sdb *db, const char *target, const sdb_rec **out, size_t max)
{
    const sdb_rec **all = xmalloc((db->n + 1) * sizeof(*all));
    size_t n = 0;
    for (size_t i = 0; i < db->n; i++)
        if (!target || !strcmp(db->v[i].t, target))
            all[n++] = &db->v[i];
    qsort(all, n, sizeof(*all), rank_cmp);
    if (n > max)
        n = max;
    memcpy(out, all, n * sizeof(*out));
    free(all);
    return n;
}

long sdb_prune(sdb *db, uint64_t min_runs, int failed_only, uint64_t older_ms)
{
    uint64_t now = plat_wall_ms();
    size_t k = 0;
    long removed = 0;
    for (size_t i = 0; i < db->n; i++) {
        sdb_rec *r = &db->v[i];
        int drop = r->runs < min_runs || (failed_only && !r->ok) ||
                   (older_ms && r->last && now > r->last && now - r->last > older_ms);
        if (drop) {
            sdb_rec_free(r);
            removed++;
        } else {
            db->v[k++] = *r;
        }
    }
    db->n = k;
    index_rebuild(db);
    return rewrite(db) < 0 ? -1 : removed;
}
