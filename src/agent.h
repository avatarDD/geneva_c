/*
 * Server-side evaluation. Geneva's server-side strategies run on the server,
 * and the connection that tests them has to come from inside the censored
 * network. "geneva agent" runs there (on a router or a PC, without root) and
 * makes the probes; the evaluator on the server sends it one request per
 * run over a control connection (ctl.h) and applies the strategy to its own
 * service port meanwhile.
 *
 *   -> {"id":1,"cmd":"auth","token":"..."}
 *   -> {"id":2,"cmd":"hello"}
 *   <- {"id":2,"ok":true,"version":"...","proto":1,"os":"linux","arch":"mipsel","probes":["http",...]}
 *   -> {"id":3,"cmd":"probe","probe":{"kind":"http","host":"example.com","ip":"203.0.113.5","port":80,...}}
 *   <- {"id":3,"ok":true,"outcome":"ok","fitness":400,"bytes":1234,"detail":"200, 1234 bytes"}
 *
 * Either side may dial: the evaluator connects to "geneva agent --listen",
 * or "geneva agent --connect" dials the evaluator's --agent-listen (an agent
 * behind NAT). The evaluator always authenticates first. Exec and external
 * probes are refused: the agent only makes network connections.
 */
#ifndef GENEVA_AGENT_H
#define GENEVA_AGENT_H

#include <signal.h>

#include "json.h"
#include "probe.h"
#include "util.h"

#define AGENT_MAX_TIMEOUT 60.0
#define AGENT_MAX_BYTES (16u << 20)

/* Writes the probe settings as the value of a "probe" key. */
void agent_probe_json(const probe_cfg *c, jw *w);
/* Reads them back. Strings point into o; payload is allocated (free it).
 * Refuses exec and external probes and out-of-range values. Returns 0 or
 * -1 with a message. */
int agent_probe_parse(const json_val *o, probe_cfg *c, sbuf *err);

/* The agent's side: ctl handler for "hello" and "probe"; ctx is an
 * agent_state. */
typedef struct {
    probe_ports ports; /* local ports of the probes (lo 0: any) */
    uint64_t probes;
} agent_state;

int agent_handler(void *ctx, const char *cmd, const json_val *req, jw *resp, sbuf *err);

/* The evaluator's side. */
typedef struct agent_conn agent_conn;

/* listen 0: connect to spec (tcp:HOST:PORT); 1: listen on spec and wait up
 * to wait_s seconds (or until *stop) for the agent to dial in. Then
 * authenticates and checks the agent's version. Returns NULL with a
 * message. */
agent_conn *agent_open(const char *spec, int listen, const char *token, double wait_s,
                       volatile sig_atomic_t *stop, sbuf *err);
/* One probe run by the agent. A lost connection is opened again once.
 * Returns 0, or -1 when the agent is gone (r says why). */
int agent_probe(agent_conn *a, const probe_cfg *c, probe_res *r);
/* "linux/mipsel 0.1.0" of the agent. */
const char *agent_name(const agent_conn *a);
void agent_close(agent_conn *a);

#endif
