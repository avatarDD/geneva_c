/*
 * Options from a file (docs/EXT_ROADMAP.md, B9): zapret2's "nfqws2 @FILE"
 * (or $FILE). The first argument of a command, @FILE or $FILE, is replaced
 * by the words of FILE, split as a shell would without running anything:
 * blanks and newlines separate words, '...' is literal, "..." keeps blanks
 * and takes \" \\ \$ \`, a backslash escapes the next character, $NAME and
 * ${NAME} are taken from the environment, # starts a comment at the start
 * of a word. $(...) and `...` are refused, as by zapret2's wordexp
 * (WRDE_NOCMD). The words need --ext.
 */
#ifndef GENEVA_EXT_CFGFILE_H
#define GENEVA_EXT_CFGFILE_H

#include <stddef.h>

#include "util.h"

#define XCFG_MAX (1 << 20) /* bytes of a file */

/* Splits text into *words (each and the array malloc'ed, NULL-terminated);
 * returns their count, or -1 with a message in err. */
int xcfg_split(const char *text, size_t len, char ***words, sbuf *err);
void xcfg_free(char **words);

/* When argv[0] is @FILE or $FILE: *argv becomes the words of FILE and the
 * arguments after it (kept for the process). Returns 1 then, 0 when there
 * is no file, -1 with a message in err (also when no word is --ext). */
int xcfg_expand(int *argc, char ***argv, sbuf *err);

#endif
