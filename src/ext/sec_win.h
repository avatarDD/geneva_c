/*
 * winws2's sandbox (docs/EXT_ROADMAP.md, N3; zapret2's nfq2/darkmagic.c,
 * win_sandbox): once packets flow, geneva run --ext on Windows
 *   - removes every privilege of its token but SeChangeNotifyPrivilege,
 *   - lowers its integrity to Low: no writes to files, registry keys and
 *     processes of Medium and above,
 *   - joins a job object that allows no child process and no access to the
 *     desktop, the clipboard and system settings.
 * There is no way back. --ext-sandbox 0 runs without it.
 *
 * Before that the files the run writes later (the autolists and their
 * debug log, --ext-state, --pidfile) get the Low label, as zapret2's
 * ensure_file_access does, and so does the WinDivert device (set_filter
 * opens a new handle); the WinDivert handles, the log and the events stay
 * open.
 */
#ifndef GENEVA_EXT_SEC_WIN_H
#define GENEVA_EXT_SEC_WIN_H

#include <stddef.h>

#include "args.h"
#include "util.h"

/* --ext-sandbox: *on is 1 on Windows unless 0 is given; 0, or -1 with a
 * message (a bad value, the option off Windows) */
int xsbx_parse(const args_t *a, int *on, sbuf *err);

/* A file written after the start (every platform keeps the list: tests) */
void xsbx_file(const char *path);
size_t xsbx_nfiles(void);
const char *xsbx_file_at(size_t i);
void xsbx_reset(void);

/* Windows: labels the files and the device, then the sandbox; 0, or -1
 * with a message. Elsewhere: 0. */
int xsbx_apply(sbuf *err);

#endif
