/* Minimal unit-test harness: no dependencies, readable failures. */
#ifndef GENEVA_TEST_H
#define GENEVA_TEST_H

#include <stdio.h>
#include <string.h>

extern int t_failures;
extern int t_checks;
extern const char *t_current;

#define CHECK(cond)                                                                       \
    do {                                                                                  \
        t_checks++;                                                                       \
        if (!(cond)) {                                                                    \
            t_failures++;                                                                 \
            fprintf(stderr, "  FAIL %s:%d [%s]: %s\n", __FILE__, __LINE__, t_current, #cond); \
        }                                                                                 \
    } while (0)

#define CHECK_INT(a, b)                                                                   \
    do {                                                                                  \
        long long _a = (long long)(a), _b = (long long)(b);                               \
        t_checks++;                                                                       \
        if (_a != _b) {                                                                   \
            t_failures++;                                                                 \
            fprintf(stderr, "  FAIL %s:%d [%s]: %s == %lld, expected %lld\n", __FILE__,    \
                    __LINE__, t_current, #a, _a, _b);                                     \
        }                                                                                 \
    } while (0)

#define CHECK_STR(a, b)                                                                   \
    do {                                                                                  \
        const char *_a = (a), *_b = (b);                                                  \
        t_checks++;                                                                       \
        if (!_a || !_b || strcmp(_a, _b) != 0) {                                          \
            t_failures++;                                                                 \
            fprintf(stderr, "  FAIL %s:%d [%s]: %s\n    got:      %s\n    expected: %s\n", \
                    __FILE__, __LINE__, t_current, #a, _a ? _a : "(null)",                \
                    _b ? _b : "(null)");                                                  \
        }                                                                                 \
    } while (0)

#define CHECK_MEM(a, alen, b, blen)                                                       \
    do {                                                                                  \
        size_t _al = (alen), _bl = (blen);                                                \
        t_checks++;                                                                       \
        if (_al != _bl || memcmp((a), (b), _al) != 0) {                                   \
            t_failures++;                                                                 \
            fprintf(stderr, "  FAIL %s:%d [%s]: %s (%zu bytes) != %s (%zu bytes)\n",       \
                    __FILE__, __LINE__, t_current, #a, _al, #b, _bl);                     \
            t_dump("got", (const unsigned char *)(a), _al);                               \
            t_dump("exp", (const unsigned char *)(b), _bl);                               \
        }                                                                                 \
    } while (0)

void t_dump(const char *label, const unsigned char *p, size_t n);

#define TEST(name) static void name(void)
#define RUN(name)          \
    do {                   \
        t_current = #name; \
        name();            \
    } while (0)

#endif
