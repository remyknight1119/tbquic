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

static QuicFlowReturn QuicServerInitialRecv(QUIC *, RPacket *,
                                        QuicLPacketFlags);
static QuicFlowReturn QuicServerInitialSend(QUIC *);
static QuicFlowReturn QuicServerHandshakeRecv(QUIC *, RPacket *,
                                        QuicLPacketFlags);
static QuicFlowReturn QuicServerHandshakeSend(QUIC *);

static QuicStatemFlow server_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .recv = QuicServerInitialRecv,
        .send = QuicServerInitialSend,
    },
    [QUIC_STATEM_HANDSHAKE] = {
        .recv = QuicServerHandshakeRecv,
        .send = QuicServerHandshakeSend,
    },
};

static QuicFlowReturn
QuicServerInitialRecv(QUIC *quic, RPacket *pkt, QuicLPacketFlags flags)
{
    return QuicInitialRecv(quic, pkt, flags); 
}

static QuicFlowReturn QuicServerInitialSend(QUIC *quic)
{
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn
QuicServerHandshakeRecv(QUIC *quic, RPacket *pkt, QuicLPacketFlags flags)
{
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn QuicServerHandshakeSend(QUIC *quic)
{
    return QUIC_FLOW_RET_FINISH;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
