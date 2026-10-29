#include <stdio.h>
#include <stdlib.h>

#include "plat.h"
#include "rng.h"
#include "test.h"

int t_failures;
int t_checks;
const char *t_current = "";

void t_dump(const char *label, const unsigned char *p, size_t n)
{
    fprintf(stderr, "    %s:", label);
    for (size_t i = 0; i < n; i++)
        fprintf(stderr, "%s%02x", i % 32 ? "" : "\n      ", p[i]);
    fprintf(stderr, "\n");
}

/* Each test file exposes one suite function. */
void suite_base(void);
void suite_pkt(void);
void suite_strategy(void);

int main(void)
{
    plat_net_init();
    rng_global_seed(12345);
    suite_base();
    suite_pkt();
    suite_strategy();
    printf("%d checks, %d failures\n", t_checks, t_failures);
    return t_failures ? 1 : 0;
}
