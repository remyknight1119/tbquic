/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "q_buff.h"

#include <assert.h>

#include "mem.h"
#include "common.h"

void QBuffQueueHeadInit(QBuffQueueHead *h)
{
    INIT_LIST_HEAD(&h->queue);
}

QBUFF *QBuffNew(size_t len, QBuffPktBuilder build_pkt)
{
    QBUFF *qb = NULL;

    qb = QuicMemCalloc(sizeof(*qb));
    if (qb == NULL) {
        return NULL;
    }

    qb->buff = QuicMemMalloc(len);
    if (qb->buff == NULL) {
        QBuffFree(qb);
        return NULL;
    }

    qb->buff_len = len;
    qb->build_pkt = build_pkt;

    return qb;
}

void QBuffFree(QBUFF *qb)
{
    QuicMemFree(qb->buff);
    QuicMemFree(qb);
}

void *QBuffHead(QBUFF *qb)
{
    return qb->buff;
}

void *QBuffTail(QBUFF *qb)
{
    return (uint8_t *)qb->buff + qb->data_len;
}

size_t QBuffLen(QBUFF *qb)
{
    return qb->buff_len;
}

size_t QBuffGetDataLen(QBUFF *qb)
{
    return qb->data_len;
}

size_t QBuffSpace(QBUFF *qb)
{
    assert(QUIC_GE(qb->buff_len, qb->data_len));

    return qb->buff_len - qb->data_len;
}

int QBuffSetDataLen(QBUFF *qb, size_t len)
{
    if (QUIC_LT(qb->buff_len, len)) {
        return -1;
    }

    qb->data_len = len;

    return 0;
}

int QBuffAddDataLen(QBUFF *qb, size_t len)
{
    return QBuffSetDataLen(qb, qb->data_len + len);
}

int QBuffBuildPkt(QUIC *quic, WPacket *pkt, QBUFF *qb, bool last)
{
    if (qb->build_pkt == NULL) {
        return -1;
    }

    return qb->build_pkt(quic, pkt, qb, last);
}

void QBuffQueueAdd(QBuffQueueHead *h, QBUFF *qb)
{
    list_add_tail(&qb->node, &h->queue);
}

void QBuffQueueDestroy(QBuffQueueHead *h)
{
    QBUFF *qb = NULL;
    QBUFF *n = NULL;

    list_for_each_entry_safe(qb, n, &h->queue, node) {
        list_del(&qb->node);
        QBuffFree(qb);
    }
}

