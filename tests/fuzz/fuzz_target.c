/*
 * One fuzz target of src/ext/fuzz.c for libFuzzer or AFL++
 * (docs/EXT_ROADMAP.md, 7.2; built by tests/fuzz/run.sh):
 *
 *   clang -fsanitize=fuzzer,address,undefined -DFUZZ_TARGET='"l7"' ...
 *
 * With -DFUZZ_STANDALONE it is a program instead, for AFL++ without its
 * libFuzzer driver and for running saved inputs again: it reads each file
 * named on its command line (stdin without one) as one input.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "ext/fuzz.h"
#include "util.h"

#ifndef FUZZ_TARGET
#  error "build with -DFUZZ_TARGET='\"NAME\"' (geneva selftest --ext --list)"
#endif

static const xfuzz_target *target;

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc, (void)argv;
    xfuzz_init();
    target = xfuzz_find(FUZZ_TARGET);
    if (!target) {
        fprintf(stderr, "no fuzz target \"%s\"\n", FUZZ_TARGET);
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n)
{
    if (!target)
        LLVMFuzzerInitialize(NULL, NULL);
    xfuzz_run(target, d, n);
    return 0;
}

#ifdef FUZZ_STANDALONE
static int one(FILE *f)
{
    sbuf b;
    char chunk[4096];
    size_t r;
    sb_init(&b);
    while ((r = fread(chunk, 1, sizeof(chunk), f)) > 0)
        sb_append(&b, chunk, r);
    LLVMFuzzerTestOneInput((const uint8_t *)b.data, b.len);
    sb_free(&b);
    return 0;
}

int main(int argc, char **argv)
{
    LLVMFuzzerInitialize(&argc, &argv);
    if (argc < 2)
        return one(stdin);
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (!f) {
            fprintf(stderr, "cannot read %s\n", argv[i]);
            return 1;
        }
        one(f);
        fclose(f);
    }
    return 0;
}
#endif
