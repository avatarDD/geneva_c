#include "rng.h"

#include "plat.h"

static uint64_t g_seed;
static int g_seeded;
static int g_thread_counter;

static _Thread_local uint64_t t_state[4];
static _Thread_local int t_ready;

static uint64_t splitmix64(uint64_t *x)
{
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

void rng_global_seed(uint64_t seed)
{
    if (seed == 0)
        plat_random_bytes(&seed, sizeof(seed));
    g_seed = seed;
    g_seeded = 1;
    /* Re-seed the calling thread so the sequence restarts deterministically. */
    t_ready = 0;
    atomic_store_int(&g_thread_counter, 0);
}

static void thread_init(void)
{
    uint64_t x;
    int idx;
    if (!g_seeded)
        rng_global_seed(0);
    idx = atomic_fetch_add_int(&g_thread_counter, 1);
    x = g_seed ^ ((uint64_t)idx * 0xD1B54A32D192ED03ULL);
    for (int i = 0; i < 4; i++)
        t_state[i] = splitmix64(&x);
    t_ready = 1;
}

static inline uint64_t rotl(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

uint64_t rng_u64(void)
{
    uint64_t *s, r, t;
    if (!t_ready)
        thread_init();
    s = t_state;
    r = rotl(s[1] * 5, 7) * 9;
    t = s[1] << 17;
    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];
    s[2] ^= t;
    s[3] = rotl(s[3], 45);
    return r;
}

uint32_t rng_u32(void) { return (uint32_t)(rng_u64() >> 32); }

int64_t rng_range(int64_t lo, int64_t hi)
{
    uint64_t span, limit, r;
    if (hi <= lo)
        return lo;
    span = (uint64_t)(hi - lo) + 1;
    if (span == 0) /* full 64-bit range */
        return (int64_t)rng_u64();
    /* Rejection sampling keeps the distribution unbiased. */
    limit = UINT64_MAX - (UINT64_MAX % span);
    do {
        r = rng_u64();
    } while (r >= limit);
    return lo + (int64_t)(r % span);
}

double rng_real(void) { return (double)(rng_u64() >> 11) * (1.0 / 9007199254740992.0); }

double rng_uniform(double a, double b) { return a + (b - a) * rng_real(); }

size_t rng_index(size_t n) { return n ? (size_t)rng_range(0, (int64_t)n - 1) : 0; }

int rng_chance(double p) { return rng_real() < p; }

void rng_bytes(void *buf, size_t n)
{
    unsigned char *p = buf;
    while (n) {
        uint64_t r = rng_u64();
        for (int i = 0; i < 8 && n; i++, n--) {
            *p++ = (unsigned char)r;
            r >>= 8;
        }
    }
}

void rng_shuffle_ptrs(void **items, size_t n)
{
    for (size_t i = n; i > 1; i--) {
        size_t j = rng_index(i);
        void *t = items[i - 1];
        items[i - 1] = items[j];
        items[j] = t;
    }
}

void rng_get_state(uint64_t s[4])
{
    if (!t_ready)
        thread_init();
    for (int i = 0; i < 4; i++)
        s[i] = t_state[i];
}

void rng_set_state(const uint64_t s[4])
{
    for (int i = 0; i < 4; i++)
        t_state[i] = s[i];
    if (!(s[0] | s[1] | s[2] | s[3]))
        t_state[0] = 1; /* the all-zero state is a fixed point */
    t_ready = 1;
}
