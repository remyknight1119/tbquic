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

int QuicStatemReadBytes(QUIC *quic, RPacket *pkt)
{
    QUIC_BUFFER *qbuf = QUIC_READ_BUFFER(quic);
    int rlen = 0;

    rlen = QuicDatagramRecvBuffer(quic, qbuf);
    if (rlen < 0) {
        return -1;
    }

    RPacketBufInit(pkt, QuicBufData(qbuf), QuicBufGetDataLength(qbuf));
    return 0;
}

static int
QuicReadStateMachine(QUIC *quic, const QuicStatemFlow *statem, size_t num)
{
    const QuicStatemFlow *sm = NULL;
    QUIC_STATEM *st = &quic->statem;
    RPacket pkt = {};
    uint32_t flag = 0;
    QuicPacketFlags flags;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int rlen = 0;

    st->read_state = QUIC_WANT_DATA;
    while (ret != QUIC_FLOW_RET_FINISH || RPacketRemaining(&pkt)) {
        if (st->read_state == QUIC_WANT_DATA && !RPacketRemaining(&pkt)) {
            rlen = quic->method->read_bytes(quic, &pkt);
            if (rlen < 0) {
                return -1;
            }

            st->read_state = QUIC_DATA_READY;
        } else {
            RPacketUpdate(&pkt);
        }

        assert(st->state >= 0 && st->state < num);
        sm = &statem[st->state];

        if (RPacketGet1(&pkt, &flag) < 0) {
            return -1;
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
                return -1;
        }
    }

    return 0;
}

int
QuicStateMachineAct(QUIC *quic, const QuicStatemFlow *statem, size_t num)
{
    const QuicStatemFlow *sm = NULL;
    QUIC_STATEM *st = &quic->statem;
    int ret = 0;

    do {
        sm = &statem[st->state];
        if (sm->pre_work != NULL) {
            ret = sm->pre_work(quic);
        }

        if (QuicSendPacket(quic) < 0) {
            return -1;
        }

        if (QuicWantWrite(quic)) {
            return -1;
        }

        if (ret < 0) {
            return -1;
        }

        ret = QuicReadStateMachine(quic, statem, num);
        if (QuicSendPacket(quic) < 0) {
            return -1;
        }

        if (QuicWantWrite(quic)) {
            return -1;
        }

        if (ret < 0) {
            return -1;
        }
    } while (st->state != QUIC_STATEM_HANDSHAKE_DONE);

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

int QuicInitialSend(QUIC *quic)
{
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH; 

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        return -1;
    }

    ret = TlsDoHandshake(&quic->tls);
    if (ret == QUIC_FLOW_RET_ERROR) {
        QUIC_LOG("TLS handshake failed\n");
        return -1;
    }

    return 0;
}

QuicFlowReturn
QuicPacketRead(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    uint32_t type = 0;

    if (QuicPktHeaderParse(quic, pkt, flags, &type) < 0) {
        QUIC_LOG("Header parse failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicHandshakeBodyParse(quic, pkt, type) < 0) {
        QUIC_LOG("Body parse failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}


