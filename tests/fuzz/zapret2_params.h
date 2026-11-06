/* Stands in for zapret2's nfq2/params.h when tests/fuzz/l7_diff.sh builds
 * nfq2/protocol.c alone: no logging, no options. */
#pragma once
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/param.h>
static struct {
    int debug;
} params;
#define DLOG(...) do {} while (0)
#define DLOG_ERR(...) do {} while (0)
#define DLOG_PERROR(...) do {} while (0)
const char *tld[6] = {"com", "org", "net", "edu", "gov", "biz"};
