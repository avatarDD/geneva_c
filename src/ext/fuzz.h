/*
 * Fuzz targets (docs/EXT_ROADMAP.md, N6 and 7.2): every reader of
 * untrusted bytes or text as one function over a buffer, with built-in
 * seed inputs and a mutator. tests/fuzz/fuzz_target.c runs a target under
 * libFuzzer or AFL++; "geneva selftest --ext --fuzz N" runs them all in
 * the binary itself (src/ext/selftest.c).
 *
 * A target never touches the network or files of its own (the profile
 * target refuses the keys that name files; pcap reads from memory). Its
 * own checks (a strategy prints back to the same text, ...) abort with a
 * message, so that a fuzzer counts them as crashes.
 */
#ifndef GENEVA_EXT_FUZZ_H
#define GENEVA_EXT_FUZZ_H

#include <stddef.h>
#include <stdint.h>

typedef void (*xfuzz_add_fn)(void *ud, const uint8_t *d, size_t n);

typedef struct {
    const char *name;
    const char *what; /* one line for "selftest --list" */
    void (*run)(const uint8_t *d, size_t n);
    void (*seeds)(xfuzz_add_fn add, void *ud);
} xfuzz_target;

const xfuzz_target *xfuzz_targets(size_t *n);
const xfuzz_target *xfuzz_find(const char *name);

/* Before the first input: --ext on (built-in blobs, triggers,
 * x-actions; again after ext_reset), logs quiet. */
void xfuzz_init(void);
/* One input through a target (the random generator reseeded first, so
 * the same input does the same). */
void xfuzz_run(const xfuzz_target *t, const uint8_t *d, size_t n);

/* A few random changes to d (n bytes, room for cap): bit flips, bytes,
 * interesting values, inserts, deletes, copies inside d and pieces of
 * other (another input, may be NULL). *rs: the generator's state. Returns
 * the new length (at most cap). */
size_t xfuzz_mutate(uint8_t *d, size_t n, size_t cap, uint64_t *rs, const uint8_t *other, size_t on);
uint64_t xfuzz_rand(uint64_t *rs);

/* A failed check of a target: prints it and aborts. */
void xfuzz_fail(const char *what, const char *file, int line);
#define XFUZZ_CHECK(c)                              \
    do {                                            \
        if (!(c))                                   \
            xfuzz_fail(#c, __FILE__, __LINE__);     \
    } while (0)

#endif
