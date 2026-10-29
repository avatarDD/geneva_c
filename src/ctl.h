/*
 * Control socket: line-delimited JSON requests and responses, plus an event
 * stream for subscribed clients. Single-threaded: the owner's poll loop
 * adds ctl_pollfds() to its own descriptors and calls ctl_dispatch().
 *
 *   -> {"id":1,"cmd":"status"}
 *   <- {"id":1,"ok":true,...}
 *   <- {"id":2,"ok":false,"error":"unknown command"}
 *
 * Built-in commands: auth {token}, ping, version, subscribe, unsubscribe.
 * Everything else goes to the owner's handler. With a token configured, a
 * client must authenticate before any command but auth and ping.
 * The protocol is described in docs/PROTOCOL.md.
 */
#ifndef GENEVA_CTL_H
#define GENEVA_CTL_H

#include <stddef.h>

#include "json.h"
#include "plat.h"
#include "util.h"

#define CTL_MAX_CLIENTS 16
#define CTL_MAX_LINE 65536
#define CTL_MAX_QUEUED (1u << 20) /* bytes of pending output per client */

typedef struct ctl ctl;

/* Fills the response object (its "id" and "ok" are written already) and
 * returns 0, or returns -1 with a message in err. Unknown commands should
 * return -1 with "unknown command". */
typedef int (*ctl_handler)(void *ctx, const char *cmd, const json_val *req, jw *resp, sbuf *err);

/* spec: "unix:/path" (POSIX), "tcp:PORT" (127.0.0.1) or "tcp:HOST:PORT"
 * ("tcp:[::1]:PORT" for IPv6). A TCP socket on a non-loopback address needs
 * a token. Port 0 picks a free port (see ctl_port). */
ctl *ctl_open(const char *spec, const char *token, sbuf *err);
/* Closes all clients and removes a unix socket file. */
void ctl_close(ctl *c);
int ctl_port(const ctl *c);

/* Number of pollfds written (at most CTL_MAX_CLIENTS + 1). */
size_t ctl_pollfds(ctl *c, plat_pollfd *fds, size_t max);
/* Handles readiness on the pollfds from ctl_pollfds. */
void ctl_dispatch(ctl *c, const plat_pollfd *fds, size_t n, ctl_handler h, void *ctx);

/* Sends an event line (with "\n") to every subscribed client. Suitable as
 * the log module's event tap. */
void ctl_broadcast(const char *line, size_t len, void *c);
int ctl_subscribers(const ctl *c);

/* ---- client side (geneva ctl) -------------------------------------------- */

/* Connects to a control socket. Returns SOCK_INVALID with a message. */
sock_t ctl_connect(const char *spec, sbuf *err);

#endif
