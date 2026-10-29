/*
 * Random numbers. Each thread owns a xoshiro256** state; with --rng-seed the
 * main thread is fully reproducible and worker threads get derived seeds.
 */
#ifndef GENEVA_RNG_H
#define GENEVA_RNG_H

#include <stddef.h>
#include <stdint.h>

/* Seeds the generator family. seed==0 means "from OS entropy". */
void rng_global_seed(uint64_t seed);
uint64_t rng_u64(void);
uint32_t rng_u32(void);
/* Uniform integer in [lo, hi] inclusive (like Python's random.randint). */
int64_t rng_range(int64_t lo, int64_t hi);
/* Uniform double in [0, 1) (like Python's random.random). */
double rng_real(void);
/* Uniform double in [a, b] (like Python's random.uniform). */
double rng_uniform(double a, double b);
/* Index in [0, n), n > 0. */
size_t rng_index(size_t n);
int rng_chance(double p);
void rng_bytes(void *buf, size_t n);
/* Fisher-Yates shuffle of an array of pointers. */
void rng_shuffle_ptrs(void **items, size_t n);
/* The calling thread's generator state, for checkpoints. */
void rng_get_state(uint64_t s[4]);
void rng_set_state(const uint64_t s[4]);

#endif
