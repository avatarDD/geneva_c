#include "ports.h"

#include <stdlib.h>

int ports_parse(const char *s, portset *ps)
{
    ps->n = 0;
    while (*s) {
        char *end;
        long lo = strtol(s, &end, 10), hi;
        if (end == s || lo < 0 || lo > 65535)
            return -1;
        hi = lo;
        s = end;
        if (*s == '-' || *s == ':') {
            const char *h = s + 1;
            hi = strtol(h, &end, 10);
            if (end == h || hi < lo || hi > 65535)
                return -1;
            s = end;
        }
        if (ps->n == MAX_PORT_RANGES)
            return -1;
        ps->lo[ps->n] = (uint16_t)lo;
        ps->hi[ps->n++] = (uint16_t)hi;
        if (*s == ',')
            s++;
        else if (*s)
            return -1;
    }
    return ps->n ? 0 : -1;
}

int ports_has(const portset *ps, uint16_t p)
{
    for (int i = 0; i < ps->n; i++)
        if (p >= ps->lo[i] && p <= ps->hi[i])
            return 1;
    return 0;
}

void ports_format(const portset *ps, sbuf *out, const char *sep_list, const char *sep_range)
{
    for (int i = 0; i < ps->n; i++) {
        if (i)
            sb_puts(out, sep_list);
        if (ps->lo[i] == ps->hi[i])
            sb_printf(out, "%u", ps->lo[i]);
        else
            sb_printf(out, "%u%s%u", ps->lo[i], sep_range, ps->hi[i]);
    }
}
