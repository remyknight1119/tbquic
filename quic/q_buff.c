/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "q_buff.h"

#include <assert.h>

#include "mem.h"
#include "format.h"
#include "quic_local.h"
#include "common.h"

static const QuicPktMethod QuicBuffPktMethod[QUIC_PKT_TYPE_MAX] = {
    [QUIC_PKT_TYPE_INITIAL] = {
        .build_pkt = QuicInitialPacketBuild,
        .get_crypto = QuicGetInitialCrypto,
        .compute_totallen = QuicInitialPacketGetTotalLen,
    },
    [QUIC_PKT_TYPE_HANDSHAKE] = {
        .build_pkt = QuicHandshakePacketBuild,
        .get_crypto = QuicGetHandshakeCrypto,
        .compute_totallen = QuicHandshakePacketGetTotalLen,
    },
    [QUIC_PKT_TYPE_1RTT] = {
        .build_pkt = QuicAppDataPacketBuild,
        .get_crypto = QuicGetOneRttCrypto,
        .compute_totallen = QuicAppDataPacketGetTotalLen,
    },
};

static const QuicPktMethod *QBuffPktMethodFind(uint32_t type)
{
    if (QUIC_GE(type, QUIC_PKT_TYPE_MAX)) {
        return NULL;
    }

    return &QuicBuffPktMethod[type];
}

void QBuffQueueHeadInit(QBuffQueueHead *h)
{
    INIT_LIST_HEAD(&h->queue);
}

QBUFF *QBuffNew(uint32_t pkt_type, size_t len)
{
    const QuicPktMethod *method = NULL;
    QBUFF *qb = NULL;

    method = QBuffPktMethodFind(pkt_type);
    if (method == NULL) {
        return NULL;
    }

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
    qb->stream_id = -1;
    qb->method = method;

    return qb;
}

void QBuffFree(QBUFF *qb)
{
    if (qb == NULL) {
        return;
    }

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
    return qb->method->build_pkt(quic, pkt, qb, last);
}

QUIC_CRYPTO *QBuffGetCrypto(QUIC *quic, QBUFF *qb)
{
    return qb->method->get_crypto(quic);
}

size_t QBufPktComputeTotalLenByType(QUIC *quic, uint32_t pkt_type,
                                    size_t data_len)
{
    if (pkt_type >= QUIC_PKT_TYPE_MAX) {
        return 0;
    }

    return QuicBuffPktMethod[pkt_type].compute_totallen(quic, data_len);
}

size_t QBufPktComputeTotalLen(QUIC *quic, QBUFF *qb)
{
    return qb->method->compute_totallen(quic, QBuffGetDataLen(qb));
}

void QBuffQueueAdd(QBuffQueueHead *h, QBUFF *qb)
{
    list_add_tail(&qb->node, &h->queue);
}

void QBuffQueueUnlink(QBUFF *qb)
{
    list_del(&qb->node);
}

bool QBuffQueueEmpty(QBuffQueueHead *h)
{
    return list_empty(&h->queue);
}

void QBuffQueueDestroy(QBuffQueueHead *h)
{
    QBUFF *qb = NULL;
    QBUFF *n = NULL;

    list_for_each_entry_safe(qb, n, &h->queue, node) {
        QBuffQueueUnlink(qb);
        QBuffFree(qb);
    }
}

static void QBufStreamFlagsProc(QUIC *quic, int64_t id, uint64_t flags)
{
    QuicStreamInstance *si = NULL;

    if (id < 0) {
        return;
    }

    si = QuicStreamGetInstance(quic, id);
    if (si == NULL) {
        return;
    }

    if (flags & QBUFF_FLAGS_STREAM_FIN) {
        if (si->send_state == QUIC_STREAM_STATE_DATA_SENT) {
            si->send_state = QUIC_STREAM_STATE_DATA_RECVD;
        }
    }

    if (flags & QBUFF_FLAGS_STREAM_RESET) {
        if (si->send_state == QUIC_STREAM_STATE_RESET_SENT) {
            si->send_state = QUIC_STREAM_STATE_RESET_RECVD;
        }
    }
}

QBUFF *QBufAckSentPkt(QUIC *quic, QBuffQueueHead *h, uint64_t smallest,
                        uint64_t largest, QBUFF *start)
{
    QBUFF *qb = NULL;
    QBUFF *n = NULL;

    if (start == NULL) {
        qb = QBUF_LAST_NODE(h);
    }

    QBUF_LIST_FOR_EACH_REVERSE(qb, n, h) {
        if (QUIC_GT(qb->pkt_num, largest)) {
            continue;
        }

        if (QUIC_GT(smallest, qb->pkt_num)) {
            return qb;
        }

        QBufStreamFlagsProc(quic, qb->stream_id, qb->flags);

        QBuffQueueUnlink(qb);
        QBuffFree(qb);
    }

    return NULL;
}

