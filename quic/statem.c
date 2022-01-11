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
#include "common.h"
#include "log.h"

static QuicFlowReturn
QuicReadStateMachine(QUIC *quic, const QuicStatemFlow *statem, size_t num)
{
    const QuicStatemFlow *sm = NULL;
    QUIC_STATEM *st = &quic->statem;
    QUIC_BUFFER *qbuf = QUIC_READ_BUFFER(quic);
    RPacket pkt = {};
    uint32_t flag = 0;
    QuicPacketFlags flags;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int rlen = 0;

    st->read_state = QUIC_WANT_DATA;
    while (ret != QUIC_FLOW_RET_FINISH || RPacketRemaining(&pkt)) {
        if (st->read_state == QUIC_WANT_DATA && !RPacketRemaining(&pkt)) {
            rlen = QuicDatagramRecvBuffer(quic, qbuf);
            if (rlen < 0) {
                return QUIC_FLOW_RET_ERROR;
            }

            RPacketBufInit(&pkt, QuicBufData(qbuf), QuicBufGetDataLength(qbuf));
            st->read_state = QUIC_DATA_READY;
        } else {
            RPacketUpdate(&pkt);
        }

        assert(st->state >= 0 && st->state < num);
        sm = &statem[st->state];

        if (RPacketGet1(&pkt, &flag) < 0) {
            return QUIC_FLOW_RET_ERROR;
        }

        flags.value = flag;
        ret = sm->recv(quic, &pkt, flags);
        switch (ret) {
            case QUIC_FLOW_RET_WANT_READ:
                st->read_state = QUIC_WANT_DATA;
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
QuicWriteStateMachine(QUIC *quic, const QuicStatemFlow *statem, size_t num)
{
    const QuicStatemFlow *sm = NULL;
    QUIC_STATEM *st = &quic->statem;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;

    while (ret != QUIC_FLOW_RET_FINISH) {
        assert(st->state >= 0 && st->state < num);
        sm = &statem[st->state];
        ret = sm->send(quic);
        if (ret == QUIC_FLOW_RET_ERROR) {
            return QUIC_FLOW_RET_ERROR;
        }
    }

    if (st->state == QUIC_STATEM_HANDSHAKE_DONE) {
        return QUIC_FLOW_RET_END;
    }

    return ret;
}

int
QuicStateMachineAct(QUIC *quic, const QuicStatemFlow *statem, size_t num)
{
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    if (QuicWantWrite(quic)) {
        if (QuicSendPacket(quic) < 0) {
            return -1;
        }

        if (QuicWantWrite(quic)) {
            return -1;
        }
    }

    while (QUIC_GET_FLOW_STATE(quic) != QUIC_FLOW_FINISHED) {
        switch (QUIC_GET_FLOW_STATE(quic)) {
            case QUIC_FLOW_READING:
                ret = QuicReadStateMachine(quic, statem, num);
                if (ret == QUIC_FLOW_RET_FINISH) {
                    QUIC_SET_FLOW_STATE(quic, QUIC_FLOW_WRITING);
                }
                break;
            case QUIC_FLOW_WRITING:
                ret = QuicWriteStateMachine(quic, statem, num);
                if (ret == QUIC_FLOW_RET_FINISH) {
                    QUIC_SET_FLOW_STATE(quic, QUIC_FLOW_READING);
                } else if (ret == QUIC_FLOW_RET_END) {
                    QUIC_SET_FLOW_STATE(quic, QUIC_FLOW_FINISHED);
                }
                break;
            default:
                return -1;
        }

        if (QuicSendPacket(quic) < 0) {
            return -1;
        }

        if (QuicWantWrite(quic)) {
            return -1;
        }

        if (ret == QUIC_FLOW_RET_ERROR) {
            return -1;
        }
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

static int
QuicLongPktParse(QUIC *quic, RPacket *pkt, QuicPacketFlags flags, uint8_t type)
{
    if (!QUIC_PACKET_IS_LONG_PACKET(flags)) {
        QUIC_LOG("Not Long packet\n");
        return -1;
    }

    if (flags.lh.lpacket_type != type) {
        QUIC_LOG("Type not match\n");
        return -1;
    }

    if (QuicLPacketHeaderParse(quic, pkt) < 0) {
        QUIC_LOG("Header Parse failed\n");
        return -1;
    }

    return 0;
}

static int
QuicShortPktParse(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    if (QUIC_PACKET_IS_LONG_PACKET(flags)) {
        QUIC_LOG("Not Short packet\n");
        return -1;
    }

    if (QuicSPacketHeaderParse(quic, pkt) < 0) {
        QUIC_LOG("Header Parse failed\n");
        return -1;
    }

    return 0;
}

QuicFlowReturn
QuicInitialRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    if (QuicLongPktParse(quic, pkt, flags, QUIC_LPACKET_TYPE_INITIAL) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicInitPacketParse(quic, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn QuicInitialSend(QUIC *quic)
{
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH; 

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    ret = TlsDoHandshake(&quic->tls);
    if (ret == QUIC_FLOW_RET_ERROR) {
        QUIC_LOG("TLS handshake failed\n");
        return ret;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn
QuicHandshakeRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    if (QuicLongPktParse(quic, pkt, flags, QUIC_LPACKET_TYPE_HANDSHAKE) < 0) {
        QUIC_LOG("Long Packet parse failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicHandshakePacketParse(quic, pkt) < 0) {
        QUIC_LOG("Handshake Packet parse failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn QuicAppDataRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    QUIC_LOG("remaining = %lu\n", RPacketRemaining(pkt));
    if (QuicShortPktParse(quic, pkt, flags)) {
        QUIC_LOG("Short packet parser failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicOneRttParse(quic, pkt) < 0) {
        QUIC_LOG("1RTT parse failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_ERROR;
}

