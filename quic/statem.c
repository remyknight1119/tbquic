/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/err.h>

#include "quic_local.h"
#include "format.h"
#include "rand.h"
#include "datagram.h"
#include "q_buff.h"
#include "mem.h"
#include "log.h"

static QuicFlowReturn
QuicReadStateMachine(QUIC *quic, QuicStatemHandler handler)
{
    QUIC_STATEM *st = &quic->statem;
    QUIC_BUFFER *qbuf = QUIC_READ_BUFFER(quic);
    RPacket pkt = {};
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int rlen = 0;

    if (handler == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    st->read_state = QUIC_WANT_DATA;
    while (ret != QUIC_FLOW_RET_FINISH) {
        if (st->read_state == QUIC_WANT_DATA) {
            rlen = QuicDatagramRecvBuffer(quic, qbuf);
            if (rlen < 0) {
                return QUIC_FLOW_RET_ERROR;
            }

            RPacketBufInit(&pkt, QuicBufData(qbuf), QuicBufGetDataLength(qbuf));
            st->read_state = QUIC_DATA_READY;
        } else {
            RPacketUpdate(&pkt);
        }

        ret = handler(quic, &pkt);
        switch (ret) {
            case QUIC_FLOW_RET_WANT_READ:
                if (!RPacketRemaining(&pkt)) {
                    st->read_state = QUIC_WANT_DATA;
                }
                continue;
            case QUIC_FLOW_RET_FINISH:
                break;
            default:
                return QUIC_FLOW_RET_ERROR;
        }
    }

    return ret;
}

static QuicFlowReturn
QuicWriteStateMachine(QUIC *quic, QuicStatemHandler handler)
{
    QBUFF *qb = NULL;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int wlen = -1;

    if (handler == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    while (ret != QUIC_FLOW_RET_FINISH && ret != QUIC_FLOW_RET_WANT_READ) {
        ret = handler(quic, NULL);
        switch (ret) {
            case QUIC_FLOW_RET_WANT_READ:
            case QUIC_FLOW_RET_FINISH:
                break;
            default:
                return QUIC_FLOW_RET_ERROR;
        }
    }

    QBUF_LIST_FOR_EACH(qb, &quic->tx_queue) {
        if (QBuffBuildPkt(quic, qb) < 0) {
            return QUIC_FLOW_RET_ERROR;
        }
    }

    wlen = QuicDatagramSend(quic);
    if (wlen < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return ret;
}

int
QuicStateMachineAct(QUIC *quic, const QuicStateMachineFlow *statem, size_t num)
{
    const QuicStateMachineFlow *sm = NULL;
    QUIC_STATEM *st = &quic->statem;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    while (QUIC_GET_FLOW_STATE(quic) != QUIC_FLOW_FINISHED) {
        assert(st->state >= 0 && st->state < num);
        sm = &statem[st->state];

        if (st->state == QUIC_STATEM_HANDSHAKE_DONE) {
            return QUIC_FLOW_RET_FINISH;
        }

        switch (QUIC_GET_FLOW_STATE(quic)) {
            case QUIC_FLOW_READING:
                ret = QuicReadStateMachine(quic, sm->recv);
                if (ret == QUIC_FLOW_RET_FINISH) {
                    QUIC_SET_FLOW_STATE(quic, QUIC_FLOW_WRITING);
                }
                break;
            case QUIC_FLOW_WRITING:
                ret = QuicWriteStateMachine(quic, sm->send);
                if (ret == QUIC_FLOW_RET_WANT_READ) {
                    QUIC_SET_FLOW_STATE(quic, QUIC_FLOW_READING);
                }
                break;
            default:
                return -1;
        }

        if (ret == QUIC_FLOW_RET_ERROR) {
            return -1;
        }
    }

    if (ret != QUIC_FLOW_RET_FINISH) {
        return -1;
    }

    return 0;
}

int QuicCidGen(QUIC_DATA *cid, size_t len)
{
    assert(cid->data == NULL);

    cid->data = QuicMemMalloc(len);
    if (cid->data == NULL) {
        return -1;
    }

    QuicRandBytes(cid->data, len);
    cid->len = len;

    return 0;
}

QuicFlowReturn QuicInitialRecv(QUIC *quic, void *packet)
{
    RPacket *pkt = packet;
    QuicLPacketFlags flags;
    uint8_t type = 0;

    if (RPacketGet1(pkt, (void *)&flags) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (!QUIC_PACKET_IS_LONG_PACKET(flags)) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicLPacketHeaderParse(quic, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    type = flags.lpacket_type;
    if (type != QUIC_LPACKET_TYPE_INITIAL) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicInitPacketParse(quic, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn QuicInitialSend(QUIC *quic, void *packet)
{
    QUIC_DATA *cid = NULL;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, quic->cid_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    ret = QuicTlsDoHandshake(&quic->tls, NULL, 0);
    if (ret == QUIC_FLOW_RET_ERROR) {
        QUIC_LOG("TLS handshake failed\n");
        return ret;
    }

    if (QuicInitialFrameBuild(quic, QuicInitialPacketBuild) < 0) {
        QUIC_LOG("Initial frame build failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    printf("client init, ret = %d\n", ret);
    return ret;
}


