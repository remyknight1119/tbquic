/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"
#include "common.h"
#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"
#include "log.h"

static QuicFlowReturn QuicServerInitialRecv(QUIC *, void *);

static QuicStateMachine server_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_READY] = {
        .flow_state = QUIC_FLOW_NOTHING, 
        .next_state = QUIC_STATEM_INITIAL_RECV,
    },
    [QUIC_STATEM_INITIAL_RECV] = {
        .flow_state = QUIC_FLOW_READING, 
        .next_state = QUIC_STATEM_INITIAL_SEND,
        .handler = QuicServerInitialRecv,
    },
};

static QuicFlowReturn QuicServerInitialRecv(QUIC *quic, void *packet)
{
    RPacket *pkt = packet;
    QUIC_BUFFER *crypto_buf = QUIC_TLS_BUFFER(quic);
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

    if (crypto_buf->data_len == 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QuicTlsDoHandshake(&quic->tls, QuicBufData(crypto_buf),
            crypto_buf->data_len);
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
