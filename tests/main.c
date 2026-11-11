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
void suite_fw(void);
void suite_ctl(void);
void suite_evolve(void);
void suite_probe(void);
void suite_censor(void);
void suite_flow(void);
void suite_ext(void);
void suite_engine(void);
void suite_crypto(void);
void suite_censor_x(void);
void suite_ctrack(void);
void suite_l7(void);
void suite_xact(void);
void suite_xact5b(void);
void suite_xcomb(void);
void suite_profile(void);
void suite_lists(void);
void suite_autolist(void);
void suite_svc(void);
void suite_fwx(void);
void suite_fuzz(void);
void suite_xseq(void);
void suite_detect(void);

int main(void)
{
    plat_net_init();
    rng_global_seed(12345);
    suite_base();
    suite_pkt();
    suite_strategy();
    suite_fw();
    suite_ctl();
    suite_evolve();
    suite_probe();
    suite_censor();
    suite_flow();
    suite_ext();
    suite_engine();
    suite_crypto();
    suite_censor_x();
    suite_ctrack();
    suite_l7();
    suite_xact();
    suite_xact5b();
    suite_xcomb();
    suite_profile();
    suite_lists();
    suite_autolist();
    suite_svc();
    suite_fwx();
    suite_fuzz();
    suite_xseq();
    suite_detect();
    printf("%d checks, %d failures\n", t_checks, t_failures);
    return t_failures ? 1 : 0;
}
