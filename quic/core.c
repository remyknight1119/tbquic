/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"

#include <assert.h>
#include "format.h"
#include "common.h"
#include "stream.h"
#include "log.h"

static int QuicCryptoOffset[QUIC_PKT_TYPE_MAX] = {
    [QUIC_PKT_TYPE_INITIAL] = offsetof(QUIC, initial),
    [QUIC_PKT_TYPE_0RTT] =  offsetof(QUIC, application),
    [QUIC_PKT_TYPE_HANDSHAKE] = offsetof(QUIC, handshake),
    [QUIC_PKT_TYPE_1RTT] =  offsetof(QUIC, application),
};

QUIC_CRYPTO *QuicCryptoGet(QUIC *quic, uint32_t pkt_type)
{
    int offset = 0;

    if (QUIC_GE(pkt_type, QUIC_PKT_TYPE_MAX)) {
        return NULL;
    }

    offset = QuicCryptoOffset[pkt_type];

    return (void *)((uint8_t *)quic + offset);
}

QUIC_CRYPTO *QuicGetInitialCrypto(QUIC *quic)
{
    return QuicCryptoGet(quic, QUIC_PKT_TYPE_INITIAL);
}

QUIC_CRYPTO *QuicGetHandshakeCrypto(QUIC *quic)
{
    return QuicCryptoGet(quic, QUIC_PKT_TYPE_HANDSHAKE);
}

QUIC_CRYPTO *QuicGetOneRttCrypto(QUIC *quic)
{
    return QuicCryptoGet(quic, QUIC_PKT_TYPE_1RTT);
}

int QuicWritePkt(QUIC *quic, QuicStaticBuffer *buffer)
{
    QBuffQueueHead *send_queue = &quic->tx_queue;
    QBUFF *qb = NULL;
    QBUFF *next = NULL;
    QBUFF *tail = NULL;
    QUIC_CRYPTO *c = NULL;
    WPacket pkt = {};
    size_t total_len = 0;
    bool end = false;
    int ret = 0;

    WPacketStaticBufInit(&pkt, buffer->data, quic->mss);
    tail = QBUF_LAST_NODE(send_queue);
    list_for_each_entry_safe(qb, next, &send_queue->queue, node) {
        if (end) {
            break;
        }
        end = qb == tail;
        if (!end) {
            total_len = QBufPktComputeTotalLen(quic, qb) + 
                            QBufPktComputeTotalLen(quic, next);
            if (QUIC_GT(total_len, WPacket_get_space(&pkt))) {
                end = true;
            }
        }

        if (QuicStreamSendFlowCtrl(quic, qb->stream_id, qb->stream_len,
                    qb->pkt_type) < 0) {
            return -1;
        }

        QUIC_LOG("last = %d, data len = %lu\n", end, QBuffGetDataLen(qb));
        ret = QBuffBuildPkt(quic, &pkt, qb, end);
        if (ret < 0) {
            QUIC_LOG("Build pkt failed\n");
            return -1;
        }

        c = QBuffGetCrypto(quic, qb);
        assert(c != NULL);

        QBuffQueueUnlink(qb);
        QBuffQueueAdd(&c->sent_queue, qb);
        if (qb == tail) {
            break;
        } 
    }

    buffer->len = WPacket_get_written(&pkt);
    WPacketCleanup(&pkt);

    return 0;
}

