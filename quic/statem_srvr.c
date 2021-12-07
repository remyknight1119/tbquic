/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"
#include "common.h"
#include "datagram.h"
#include "packet_format.h"
#include "packet_local.h"

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
    uint32_t flags = 0;

    printf("xxxxxxxxxxxxxxxxxxxxxxxxxxready\n");
    while (RPacketGet1(pkt, &flags) >= 0) {
        if (QuicPacketParse(quic, pkt, flags) < 0) {
            return -1;
        }
        RPacketHeadSync(pkt);
    }

    return 0;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
