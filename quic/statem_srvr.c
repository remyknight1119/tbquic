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

static QuicFlowReturn QuicServerInitialRecv(QUIC *, void *);
static QuicFlowReturn QuicServerInitialSend(QUIC *, void *);

static QuicStateMachineFlow server_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .recv = QuicServerInitialRecv,
        .send = QuicServerInitialSend,
    },
};

static QuicFlowReturn QuicServerInitialRecv(QUIC *quic, void *packet)
{
    return QuicInitialRecv(quic, packet); 
}

static QuicFlowReturn QuicServerInitialSend(QUIC *quic, void *packet)
{
    return QUIC_FLOW_RET_ERROR;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
