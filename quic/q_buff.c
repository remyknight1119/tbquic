/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "q_buff.h"

#include "mem.h"

void QBuffHeadInit(QBuffHead *h)
{
    INIT_LIST_HEAD(&h->queue);
}

QBuff *QBufNew(size_t len)
{
    QBuff *qb = NULL;

    qb = QuicMemMalloc(sizeof(*qb));
    if (qb == NULL) {
        return NULL;
    }

    qb->buff = QuicMemMalloc(len);
    if (qb->buff == NULL) {
        QBufFree(qb);
        return NULL;
    }

    qb->len = len;
    return qb;
}

void QBufFree(QBuff *qb)
{
    QuicMemFree(qb->buff);
    QuicMemFree(qb);
}

void QBuffQueueDestroy(QBuffHead *h)
{
    QBuff *qb = NULL;
    QBuff *n = NULL;

    list_for_each_entry_safe(qb, n, &h->queue, node) {
        list_del(&qb->node);
        QBufFree(qb);
    }
}

