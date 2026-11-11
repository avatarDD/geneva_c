/*
 * "geneva selftest --ext" (docs/EXT_ROADMAP.md, N6): the fuzz targets of
 * src/ext/fuzz.c in the binary. Only in a build with the extensions; the
 * command is not in the list of "geneva --help" without them.
 */
#ifndef GENEVA_EXT_SELFTEST_H
#define GENEVA_EXT_SELFTEST_H

int xcmd_selftest(int argc, char **argv);

#endif
