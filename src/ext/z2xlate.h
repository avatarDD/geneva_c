/*
 * nfqws2's desync options into a geneva strategy (X12b): the lines of
 * zapret2's blockcheck2 grid ("--payload=tls_client_hello
 * --lua-desync=fake:blob=fake_default_tls:ip_ttl=3 --lua-desync=multisplit")
 * as one tree of x-actions (docs/EXT.md, X5a-X5c).
 *
 * Each --lua-desync is an instance; the --payload and --out-range before it
 * filter which packets it sees, and the instances run in their order on
 * each packet, a dropped packet still going on to the next ones. In geneva
 * that is nesting: an instance is an x-action whose subtree gets the packet
 * it passed or dropped, and a filter is an xwhen around the instances that
 * share it, its "else" being the instances after them:
 *
 *   --payload=quic_initial --lua-desync=send:ipfrag --lua-desync=drop
 *   [FLOW:n:a]-xwhen{iff=L7:payload:quic_initial}(xsend{ipfrag}(drop,),)-| \/
 */
#ifndef GENEVA_EXT_Z2XLATE_H
#define GENEVA_EXT_Z2XLATE_H

#include "util.h"

/* args: the options separated by spaces. On success the strategy goes to
 * out (appended) and 0 is returned; -1 with err for what geneva has no
 * equivalent of (luaexec, --blob files) or a malformed option. Arguments
 * are not checked here: strategy_parse() does that. */
int z2x_translate(const char *args, sbuf *out, sbuf *err);

#endif
