/*
 * What fw.c shares with the BSD rules (fw_bsd.c).
 */
#ifndef GENEVA_FW_INT_H
#define GENEVA_FW_INT_H

#include "fw.h"

#define FW_IPFW_FIRST 50 /* ipfw: our rule number is the lowest free one from here */

#ifndef _WIN32
/* name in $PATH or the usual sbin directories: 0 with the path, or -1 */
int fw_find_bin(const char *name, char *out, size_t cap);
/* runs argv (stdin from input, NULL: /dev/null), stdout and stderr into
 * output (NULL: dropped); the exit status, or -1 when it did not run */
int fw_run_argv(char *const argv[], const char *input, sbuf *output);
void fw_trim(sbuf *s);
#endif

/* the interfaces to match: --iface, or its list under --ext; 0: any */
int fw_ifaces(const fw_config *c, const char **v);

/* ipfw and pf (any platform: printing and tests) */
int fw_bsd_check(const fw_config *c, fw_backend b, sbuf *err);
void fw_ipfw_rules(const fw_config *c, const char *rule, sbuf *out);
void fw_pf_rules(const fw_config *c, sbuf *out);
void fw_bsd_script(const fw_config *c, fw_backend b, int up, sbuf *out);
#if defined(__FreeBSD__) || defined(__OpenBSD__)
int fw_bsd_up(fw_config *c, sbuf *err);
void fw_bsd_down(const fw_config *c);
#endif

#endif
