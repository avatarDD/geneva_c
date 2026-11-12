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

/* one queue and one raw sender per worker (--ext-workers: queue + i) */
typedef struct {
    nfq **q;
    rawsend **rs;
    unsigned n;
    int fw_on;
} nfq_state;

/* the NFQUEUE packet id first, then what the extensions read (meta);
 * detached: the packet was dropped, the verdict sends it anew */
typedef struct {
    uint32_t id, mark, indev, outdev, detached;
} nfq_pctx;

static int nfq_be_verdict(eng_worker *w, const void *pctx, int accept, const uint8_t *data, size_t len)
{
    nfq_state *s = w->e->bs;
    uint32_t id;
    memcpy(&id, pctx, sizeof(id));
    if (((const nfq_pctx *)pctx)->detached) {
        nfq_pctx c;
        memcpy(&c, pctx, sizeof(c));
        if (!accept)
            return 0;
        /* with the packet's own mark (routing) besides the engine's */
        if (!data || rawsend_send_x(s->rs[w->id], data, len, c.mark, NULL) < 0) {
            LOGD("engine", "sending held packet %u: %s", id, data ? strerror(errno) : "no bytes");
            return -1;
        }
        return 0;
    }
    if (nfq_verdict(s->q[w->id], id, accept ? NFQ_ACCEPT : NFQ_DROP, data, len, 0, 0) < 0) {
        LOGW("engine", "verdict for packet %u failed: %s", id, strerror(errno));
        return -1;
    }
    return 0;
}

static int nfq_be_inject(eng_worker *w, const void *pctx, const uint8_t *data, size_t len)
{
    nfq_state *s = w->e->bs;
    if (rawsend_send(s->rs[w->id], data, len) < 0) {
        LOGD("engine", "raw send: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static int nfq_be_inject_x(eng_worker *w, const void *pctx, const uint8_t *data, size_t len, uint32_t mark,
                           const char *ifout)
{
    nfq_state *s = w->e->bs;
    (void)pctx;
    if (rawsend_send_x(s->rs[w->id], data, len, mark, ifout) < 0) {
        LOGD("engine", "raw send: %s", strerror(errno));
        return -1;
    }
    return 0;
}

static void nfq_be_meta(const void *pctx, uint32_t *mark, uint32_t *ifin, uint32_t *ifout)
{
    nfq_pctx c;
    memcpy(&c, pctx, sizeof(c));
    *mark = c.mark, *ifin = c.indev, *ifout = c.outdev;
}

static void nfq_be_detach(const void *pctx, void *out)
{
    nfq_pctx c;
    memcpy(&c, pctx, sizeof(c));
    c.detached = 1;
    memcpy(out, &c, sizeof(c));
}

static void on_msg(const nfq_msg *m, void *ctx)
{
    eng_worker *w = ctx;
    nfq_pctx id = {m->id, m->mark, m->indev, m->outdev, 0};
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
    engine_packet(w, m->data, m->len, dir, &id);
}

static void pass_msg(const nfq_msg *m, void *ctx)
{
    nfq_pctx id = {m->id, m->mark, m->indev, m->outdev, 0};
    nfq_be_verdict(ctx, &id, 1, NULL, 0);
}

static int nfq_be_open(engine *e, sbuf *err)
{
    engine_opts *o = e->o;
    nfq_state *s = xcalloc(1, sizeof(*s));
    nfq_config qc;
    int errnum;

    e->bs = s;
    s->n = e->nw ? e->nw : 1;
    s->q = xcalloc(s->n, sizeof(*s->q));
    s->rs = xcalloc(s->n, sizeof(*s->rs));
    for (unsigned i = 0; i < s->n; i++) {
        memset(&qc, 0, sizeof(qc));
        qc.queue = (uint16_t)(o->fw.queue + i);
        qc.maxlen = o->queue_maxlen;
        qc.fail_open = o->fail_open;
        qc.rcvbuf = 4 << 20;
        s->q[i] = nfq_open(&qc, &errnum, err);
        if (!s->q[i]) {
            e->err_where = "nfqueue";
            return (errnum == EPERM || errnum == EACCES || errnum == EPROTONOSUPPORT) ? EXIT_PRIV : EXIT_FAIL;
        }
        s->rs[i] = rawsend_open(o->fw.mark, err);
        if (!s->rs[i]) {
            e->err_where = "rawsend";
            return EXIT_PRIV;
        }
        if (err->len) {
            if (!i)
                LOGW("engine", "%s", err->data);
            sb_reset(err);
        }
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
    if (s->n > 1)
        LOGI("engine", "listening on NFQUEUE %u-%u", o->fw.queue, o->fw.queue + s->n - 1);
    else
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
    /* packets queued while the rules came down pass unchanged (the
     * workers' threads have ended) */
    plat_mutex_lock(&e->lock);
    for (unsigned i = 0; i < s->n; i++)
        while (s->q[i] && nfq_read(s->q[i], pass_msg, &e->w[i], NULL) > 0)
            ;
    plat_mutex_unlock(&e->lock);
}

static void nfq_be_close(engine *e)
{
    nfq_state *s = e->bs;
    if (!s)
        return;
    for (unsigned i = 0; i < s->n; i++) {
        nfq_close(s->q[i]);
        rawsend_close(s->rs[i]);
    }
    free(s->q);
    free(s->rs);
    free(s);
    e->bs = NULL;
}

static size_t nfq_be_pollfds(engine *e, plat_pollfd *fds, size_t max)
{
    nfq_state *s = e->bs;
    if (!max || e->threaded) /* the workers poll their own */
        return 0;
    fds[0].fd = nfq_fd(s->q[0]);
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    return 1;
}

/* a batch of worker w's queue, then back to its timers */
static int read_batch(eng_worker *w)
{
    nfq_state *s = w->e->bs;
    for (int i = 0; i < 64; i++) {
        int r = nfq_read(s->q[w->id], on_msg, w, &w->c.overruns);
        if (r < 0) {
            LOGE("engine", "NFQUEUE %u read: %s", w->e->o->fw.queue + w->id, strerror(errno));
            return -1;
        }
        if (r == 0)
            break;
    }
    return 0;
}

static int nfq_be_ready(engine *e, const plat_pollfd *fds, size_t n)
{
    if (!n || !(fds[0].revents & POLLIN))
        return 0;
    return read_batch(&e->w[0]);
}

static sock_t nfq_be_worker_fd(eng_worker *w)
{
    nfq_state *s = w->e->bs;
    return nfq_fd(s->q[w->id]);
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
    0,    /* --first: conntrack in the rules */
    NULL, /* no capture filter: rules */
    NULL,
    nfq_be_meta,
    nfq_be_inject_x,
    nfq_be_detach,
    nfq_be_worker_fd,
    read_batch,
};

#endif
