/*
 * Extensions of "geneva ... --ext" (docs/EXT_ROADMAP.md). Everything under
 * src/ext/ is compiled only with EXT=1 (the default); "make EXT=0" leaves
 * the directory out and the switch in src/ext_opt.c refuses --ext.
 */
#ifndef GENEVA_EXT_EXT_H
#define GENEVA_EXT_EXT_H

/* Names that "version --json" adds to "features" in a build with the
 * extensions; NULL-terminated. Integrators switch on these. */
extern const char *const ext_features[];

#endif
