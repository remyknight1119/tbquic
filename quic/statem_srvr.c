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
                                        QuicPacketFlags);
static QuicFlowReturn QuicServerInitialSend(QUIC *);
static QuicFlowReturn QuicServerHandshakeSend(QUIC *);

static QuicStatemFlow server_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .recv = QuicServerInitialRecv,
        .send = QuicServerInitialSend,
    },
    [QUIC_STATEM_HANDSHAKE] = {
        .recv = QuicPacketRead,
        .send = QuicServerHandshakeSend,
    },
    [QUIC_STATEM_HANDSHAKE_DONE] = {
        .recv = QuicPacketRead,
        .send = QuicServerHandshakeSend,
    },
};

static uint8_t h3[] =
    "\x00\x04\x19\x01\x80\x01\x00\x00\x06\x80\x00\x40\x00\x07\x40\x64"
    "\xc0\x00\x00\x04\xd7\x92\xfe\xec\xb6\x99\xd0\x12\xc0\x00\x00\x0d"
    "\xcc\xa6\x0b\x11\x00";
static QuicFlowReturn
QuicServerInitialRecv(QUIC *quic, RPacket *pkt, QuicPacketFlags flags)
{
    QuicFlowReturn ret;
    ret = QuicInitialRecv(quic, pkt, flags); 


    if (quic->tls.handshake_state == TLS_ST_SR_FINISHED ||
            quic->tls.handshake_state == TLS_ST_HANDSHAKE_DONE) {
            QUIC_LOG("Build Stream frame\n");
        if (QuicStreamFrameBuild(quic, h3, sizeof(h3) - 1) < 0) {
            QUIC_LOG("Build Stream frame failed\n");
        }
    }

    if (ret != QUIC_FLOW_RET_ERROR) {
        quic->statem.state = QUIC_STATEM_HANDSHAKE;
    }
    return ret;
}

static QuicFlowReturn QuicServerInitialSend(QUIC *quic)
{
    QuicFlowReturn ret;

    ret = QuicInitialSend(quic);
    return ret;
}

static QuicFlowReturn QuicServerHandshakeSend(QUIC *quic)
{
    return QUIC_FLOW_RET_FINISH;
}

int QuicAccept(QUIC *quic)
{
    return QuicStateMachineAct(quic, server_statem, QUIC_NELEM(server_statem));
}
