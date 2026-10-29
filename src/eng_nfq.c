/*
 * Linux packet backend: NFQUEUE for capture and verdicts, raw sockets for
 * extra packets, iptables/nftables rules that feed the queue.
 */
#include "engine_int.h"

#ifdef __linux__

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "geneva.h"
#include "log.h"
#include "nfq.h"
#include "rawsend.h"

typedef struct {
    nfq *q;
    rawsend *rs;
    int fw_on;
} nfq_state;

typedef uint32_t nfq_pctx; /* the NFQUEUE packet id */

static int nfq_be_verdict(engine *e, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    nfq_state *s = e->bs;
    uint32_t id;
    memcpy(&id, pctx, sizeof(id));
    if (nfq_verdict(s->q, id, accept ? NFQ_ACCEPT : NFQ_DROP, data, len, 0, 0) < 0) {
        LOGW("engine", "verdict for packet %u failed: %s", id, strerror(errno));
        return -1;
    }
    return 0;
}

static int nfq_be_inject(engine *e, const void *pctx, const uint8_t *data, size_t len)
{
    nfq_state *s = e->bs;
    if (rawsend_send(s->rs, data, len) < 0) {
        LOGD("engine", "raw send: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void on_msg(const nfq_msg *m, void *ctx)
{
    engine *e = ctx;
    nfq_pctx id = m->id;
    int dir;
    switch (m->hook) {
    case NFQ_HOOK_PRE_ROUTING:
    case NFQ_HOOK_LOCAL_IN:
        dir = DIR_IN;
        break;
    case NFQ_HOOK_LOCAL_OUT:
    case NFQ_HOOK_POST_ROUTING:
        dir = DIR_OUT;
        break;
    default:
        dir = -1; /* FORWARD: by the ports */
    }
    engine_packet(e, m->data, m->len, dir, &id);
}

static void pass_msg(const nfq_msg *m, void *ctx)
{
    nfq_pctx id = m->id;
    nfq_be_verdict(ctx, &id, 1, NULL, 0);
}

static int nfq_be_open(engine *e, sbuf *err)
{
    engine_opts *o = e->o;
    nfq_state *s = xcalloc(1, sizeof(*s));
    nfq_config qc;
    int errnum;

    e->bs = s;
    memset(&qc, 0, sizeof(qc));
    qc.queue = o->fw.queue;
    qc.maxlen = o->queue_maxlen;
    qc.fail_open = o->fail_open;
    qc.rcvbuf = 4 << 20;
    s->q = nfq_open(&qc, &errnum, err);
    if (!s->q) {
        e->err_where = "nfqueue";
        return (errnum == EPERM || errnum == EACCES || errnum == EPROTONOSUPPORT) ? EXIT_PRIV : EXIT_FAIL;
    }
    s->rs = rawsend_open(o->fw.mark, err);
    if (!s->rs) {
        e->err_where = "rawsend";
        return EXIT_PRIV;
    }
    if (err->len) {
        LOGW("engine", "%s", err->data);
        sb_reset(err);
    }
    if (o->apply_fw) {
        if (fw_up(&o->fw, err) < 0) {
            e->err_where = "firewall";
            return EXIT_FIREWALL;
        }
        s->fw_on = 1;
        e->fw_name = fw_backend_name(o->fw.backend);
        LOGI("engine", "firewall rules applied (%s)", e->fw_name);
    }
    LOGI("engine", "listening on NFQUEUE %u", o->fw.queue);
    return EXIT_OK;
}

static void nfq_be_stop(engine *e)
{
    nfq_state *s = e->bs;
    if (!s)
        return;
    if (s->fw_on) {
        fw_down(&e->o->fw);
        s->fw_on = 0;
    }
    if (s->q) {
        /* packets queued while the rules came down pass unchanged */
        plat_mutex_lock(&e->lock);
        while (nfq_read(s->q, pass_msg, e, NULL) > 0)
            ;
        plat_mutex_unlock(&e->lock);
    }
}

static void nfq_be_close(engine *e)
{
    nfq_state *s = e->bs;
    if (!s)
        return;
    nfq_close(s->q);
    rawsend_close(s->rs);
    free(s);
    e->bs = NULL;
}

static size_t nfq_be_pollfds(engine *e, plat_pollfd *fds, size_t max)
{
    nfq_state *s = e->bs;
    if (!max)
        return 0;
    fds[0].fd = nfq_fd(s->q);
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return 1;
}

static int nfq_be_ready(engine *e, const plat_pollfd *fds, size_t n)
{
    nfq_state *s = e->bs;
    if (!n || !(fds[0].revents & POLLIN))
        return 0;
    /* drain a batch, but keep timers responsive */
    for (int i = 0; i < 64; i++) {
        int r = nfq_read(s->q, on_msg, e, &e->c.overruns);
        if (r < 0) {
            LOGE("engine", "NFQUEUE read: %s", strerror(errno));
            return -1;
        }
        if (r == 0)
            break;
    }
    return 0;
}

const backend nfq_backend = {
    "nfqueue",
    sizeof(nfq_pctx),
    nfq_be_open,
    nfq_be_stop,
    nfq_be_close,
    nfq_be_pollfds,
    nfq_be_ready,
    nfq_be_verdict,
    nfq_be_inject,
};

#endif
