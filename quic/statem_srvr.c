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
    return QuicInitialRecv(quic, packet); 
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
