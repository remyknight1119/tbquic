/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "connection.h"

#include <assert.h>
#include "mem.h"
#include "rand.h"
#include "common.h"

int QuicCidGen(QUIC_DATA *id, size_t len)
{
    assert(id->data == NULL);

    id->data = QuicMemMalloc(len);
    if (id->data == NULL) {
        return -1;
    }

    QuicRandBytes(id->data, len);
    id->len = len;

    return 0;
}

QuicCid *QuicCidAlloc(uint64_t seq)
{
    QuicCid *cid = NULL;

    cid = QuicMemCalloc(sizeof(*cid));
    if (cid == NULL) {
        return NULL;
    }

    cid->seq = seq;

    return cid;
}

void QuicCidFree(QuicCid *cid)
{
    if (cid == NULL) {
        return;
    }

    QuicDataFree(&cid->id);
    QuicMemFree(cid);
}

static void QuicCidUnlinkAndFree(QuicCid *cid)
{
    if (cid == NULL) {
        return;
    }

    list_del(&cid->node);
    QuicCidFree(cid);
}

void QuicCidAdd(QuicCidPool *p, QuicCid *id)
{
    list_add_tail(&id->node, &p->queue);
    p->num++;
}

QuicCid *QuicCidIssue(QuicCidPool *p, size_t id_len)
{
    QuicCid *cid = NULL;

    cid = QuicCidAlloc(p->max_seq);
    if (cid == NULL) {
        return NULL;
    }

    if (QuicCidGen(&cid->id, id_len) < 0) {
        goto err;
    }

    QuicRandBytes(cid->stateless_reset_token,
            sizeof(cid->stateless_reset_token));
    QuicCidAdd(p, cid);
    p->max_seq++;

    return cid;
err:
    QuicCidFree(cid);
    return NULL;
}

QuicCid *QuicCidFind(QuicCidPool *p, uint64_t seq)
{
    QuicCid *cid = NULL;

    if (QUIC_GE(seq, p->max_seq)) {
        return NULL;
    }

    list_for_each_entry(cid, &p->queue, node) {
        if (QUIC_GT(cid->seq, seq)) {
            break;
        }

        if (cid->seq == seq) {
            return cid;
        }
    }

    return NULL;
}

int QuicCidRetire(QuicCidPool *p, uint64_t seq)
{
    QuicCid *cid = NULL;

    cid = QuicCidFind(p, seq);
    if (cid == NULL) {
        return -1;
    }

    QuicCidUnlinkAndFree(cid);
    p->num--;
    return 0;
}

void QuicCidRetirePriorTo(QuicCidPool *p, uint64_t prior_to)
{
    QuicCid *cid = NULL;
    QuicCid *n = NULL;

    list_for_each_entry_safe(cid, n, &p->queue, node) {
        if (QUIC_GE(cid->seq, prior_to)) {
            break;
        }

        QuicCidUnlinkAndFree(cid);
        p->num--;
    }
}

static int QuicCidPoolInit(QuicCidPool *p)
{
    QuicMemset(p, 0, sizeof(*p));
    INIT_LIST_HEAD(&p->queue);
    return 0;
}

static void QuicCidPoolDestroy(QuicCidPool *p)
{  
    QuicCid *cid = NULL;
    QuicCid *n = NULL;

    list_for_each_entry_safe(cid, n, &p->queue, node) {
        QuicCidUnlinkAndFree(cid);
    }
}

int QuicActiveCidLimitCheck(QuicCidPool *p, uint64_t limit)
{
    if (QUIC_GE(p->num, limit)) {
        return -1;
    }

    return 0;
}

int QuicConnInit(QuicConn *c)
{
    if (QuicCidPoolInit(&c->dcid) < 0) {
        return -1;
    }

    return QuicCidPoolInit(&c->scid);
}

void QuicConnFree(QuicConn *c)
{
    QuicCidPoolDestroy(&c->scid);
    QuicCidPoolDestroy(&c->dcid);
}
