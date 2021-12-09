/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/err.h>

#include "quic_local.h"
#include "packet_format.h"
#include "datagram.h"
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
                if (st->rwstate == QUIC_READING) {
                    return QUIC_FLOW_RET_WANT_READ;
                }

                return QUIC_FLOW_RET_ERROR;
            }

            RPacketBufInit(&pkt, QuicBufData(qbuf), QuicBufGetDataLength(qbuf));
            st->read_state = QUIC_WANT_DATA;
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
    QUIC_BUFFER *qbuf = QUIC_WRITE_BUFFER(quic);
    WPacket pkt = {};
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int wlen = -1;

    if (handler == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    while (ret != QUIC_FLOW_RET_FINISH) {
        WPacketBufInit(&pkt, qbuf->buf);
        ret = handler(quic, &pkt);
        QuicBufSetDataLength(qbuf, WPacket_get_written(&pkt));
        WPacketCleanup(&pkt);
        switch (ret) {
            case QUIC_FLOW_RET_WANT_READ:
            case QUIC_FLOW_RET_FINISH:
                break;
            default:
                return QUIC_FLOW_RET_ERROR;
        }

        wlen = QuicDatagramSendBuffer(quic, qbuf);
        if (wlen < 0) {
            return QUIC_FLOW_RET_ERROR;
        }

        if (ret == QUIC_FLOW_RET_WANT_READ) {
            break;
        }
    }

    return ret;
}

int
QuicStateMachineAct(QUIC *quic, const QuicStateMachine *statem, size_t num)
{
    const QuicStateMachine *sm = NULL;
    QUIC_STATEM *st = &quic->statem;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    assert(st->state >= 0 && st->state < num);
    sm = &statem[st->state];

    while (!QUIC_FLOW_STATEM_FINISHED(sm->flow_state)) {
        switch (sm->flow_state) {
            case QUIC_FLOW_NOTHING:
                ret = QUIC_FLOW_RET_CONTINUE;
                break;
            case QUIC_FLOW_READING:
                ret = QuicReadStateMachine(quic, sm->handler);
                break;
            case QUIC_FLOW_WRITING:
                ret = QuicWriteStateMachine(quic, sm->handler);
                break;
            default:
                QUIC_LOG("Unknown flow state(%d)\n", sm->flow_state);
                return -1;
        }

        st->state = sm->next_state;
        assert(st->state >= 0 && st->state < num);
        sm = &statem[st->state];
        if (ret != QUIC_FLOW_RET_CONTINUE) {
            break;
        }
    }

    return ret;
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

    if (QuicInitPacketPaser(quic, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}


