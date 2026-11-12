/*
 * The policy of --ext (docs/EXT_ROADMAP.md, 4.6; docs/EXT.md, X10b): the
 * state of each key (port, /24 or /48, address, host name, as the detector
 * names them) as an immutable snapshot the workers read without a lock.
 *
 * One writer (the engine's main thread: the detector's events) changes the
 * keys and publishes a new snapshot; the workers are the readers. A reader
 * reads only inside xpol_enter() .. xpol_leave() (the packet hook) and is
 * quiescent outside; a snapshot that was replaced is freed once every
 * reader was quiescent since (QSBR, by generations: a reader announces the
 * generation it entered with, a replaced snapshot waits for every reader
 * that announced an older one). No reader ever waits.
 *
 * For now a key is HEALTHY (not in the snapshot) or IMPAIRED (the
 * detector of --ext-auto said so); the tuner's TRIAL and TREAT come with X11.
 * The surgical path lets a connection go past the queue only when none of
 * its keys is impaired.
 */
#ifndef GENEVA_EXT_POLICY_H
#define GENEVA_EXT_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "json.h"

enum { XPOL_HEALTHY = 0, XPOL_IMPAIRED };

#define XPOL_KEYS 4  /* port, net, address, host (detect.h's XK_*) */
#define XPOL_SLOTS 4 /* snapshots alive at once: the current and the replaced */

typedef struct xpol_snap xpol_snap;

/* Before the readers start: n readers (the workers), ids 0..n-1. */
void xpol_init(unsigned readers);
/* After they stopped: everything freed. */
void xpol_free(void);

/* ---- the writer ---- */

/* The state of key (XPOL_HEALTHY removes it). Takes effect with the next
 * xpol_publish(). */
void xpol_set(const char *key, int state);
/* A new snapshot when something changed, and the replaced ones whose
 * readers all moved on freed. Called after changes and from time to time
 * (a reader that was busy blocks a free; the next call takes it). Returns
 * 1 when a snapshot was published. */
int xpol_publish(void);
/* The generation of the current snapshot and its count of keys */
void xpol_stats(unsigned *gen, size_t *keys, size_t *pending);

/* ---- the readers ---- */

/* Reader r enters: the current snapshot (never NULL after xpol_init) */
const xpol_snap *xpol_enter(unsigned r);
/* Reader r is quiescent: it keeps no pointer into a snapshot */
void xpol_leave(unsigned r);
/* The keys in s (0: nothing to look up) */
size_t xpol_count(const xpol_snap *s);
/* The state of one key in s */
int xpol_state(const xpol_snap *s, const char *key);
/* Is any of the keys (NULL or "" skipped) impaired in s? */
int xpol_any_impaired(const xpol_snap *s, const char *const keys[XPOL_KEYS]);

/* "policy": {"gen":..,"keys":..} */
void xpol_json(jw *w);

#endif
