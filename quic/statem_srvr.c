/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"
#include "common.h"
#include "datagram.h"
#include "format.h"
#include "packet_local.h"
#include "log.h"

static QuicFlowReturn QuicServerInitialRecv(QUIC *, RPacket *, QuicPacketFlags);

static QuicStatemFlow server_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .recv = QuicServerInitialRecv,
    },
    [QUIC_STATEM_HANDSHAKE] = {
        .pre_work = QuicInitialSend,
        .recv = QuicPacketRead,
    },
    [QUIC_STATEM_HANDSHAKE_DONE] = {
        .recv = QuicPacketRead,
    },
    [QUIC_STATEM_CLOSING] = {
        .recv = QuicPacketClosingRecv,
    },
    [QUIC_STATEM_DRAINING] = {
        .recv = QuicPacketDrainingRecv,
    },
};

static QuicFlowReturn
QuicServerInitialRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    QuicFlowReturn ret;
    ret = QuicInitialRecv(quic, pkt, flags); 
    if (ret != QUIC_FLOW_RET_ERROR) {
        quic->statem.state = QUIC_STATEM_HANDSHAKE;
    }
    QuicBufClear(QUIC_TLS_BUFFER(quic));
    return ret;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
