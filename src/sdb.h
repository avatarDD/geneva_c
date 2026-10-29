/*
 * Local database of evaluated strategies: one JSON Lines file, no SQLite.
 *
 * Every line is a record for a (strategy, target) pair with counters that
 * add up: a new evaluation appends a line with runs = 1, and loading the
 * file merges the lines. Compaction rewrites the file with one line per
 * pair (temporary file + rename, so a crash never loses the database).
 *
 *   {"s":"[TCP:flags:S]-drop-| \/","t":"http:example.com","runs":3,"ok":2,
 *    "fit_sum":512.5,"fit_best":397,"first":1730000000000,"last":...,"last_ok":...}
 *
 * The target is a free-form profile of what was tested (probe, host, port,
 * network) so that results for different censors do not mix.
 */
#ifndef GENEVA_SDB_H
#define GENEVA_SDB_H

#include <stddef.h>
#include <stdint.h>

#include "util.h"

typedef struct {
    char *s; /* canonical strategy */
    char *t; /* target profile */
    uint64_t runs, ok;
    double fit_sum, fit_best;
    uint64_t first, last, last_ok; /* ms since the epoch; 0 = never */
} sdb_rec;

typedef struct sdb sdb;

/* Opens (or creates on first write) the database at path. Malformed lines
 * are skipped with a warning. Returns NULL with a message on I/O errors. */
sdb *sdb_open(const char *path, sbuf *err);
/* Compacts the file if it grew well past its record count, then frees. */
void sdb_close(sdb *db);

/* Records one evaluation (ok = the strategy got through). Returns 0 or -1. */
int sdb_add(sdb *db, const char *strategy, const char *target, double fitness, int ok);
/* Merges a whole record (import). */
int sdb_merge(sdb *db, const sdb_rec *r);

size_t sdb_count(const sdb *db);
const sdb_rec *sdb_get(const sdb *db, size_t i);
const sdb_rec *sdb_find(const sdb *db, const char *strategy, const char *target);

/* Records for the target (NULL = all), best first: success rate (with at
 * least one success), then average fitness, then runs. Returns how many
 * pointers were stored in out (at most max). */
size_t sdb_top(const sdb *db, const char *target, const sdb_rec **out, size_t max);

/* Removes records: fewer than min_runs runs, no success when failed_only,
 * or not seen for older_ms (0 = keep all ages). Rewrites the file.
 * Returns the number removed, or -1. */
long sdb_prune(sdb *db, uint64_t min_runs, int failed_only, uint64_t older_ms);
/* Rewrites the file with one line per record. */
int sdb_compact(sdb *db);

/* One record as a JSON object (the file's line format). */
void sdb_rec_json(const sdb_rec *r, sbuf *out);
/* Parses a line; returns 0 or -1. The strings in r are allocated. */
int sdb_rec_parse(const char *line, sdb_rec *r);
void sdb_rec_free(sdb_rec *r);

#endif
