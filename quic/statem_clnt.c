/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/rand.h>

#include "quic_local.h"
#include "format.h"
#include "common.h"
#include "datagram.h"
#include "mem.h"
#include "rand.h"
#include "log.h"

static QuicFlowReturn QuicClientInitialRecv(QUIC *, RPacket *,
                                            QuicLPacketFlags);
static QuicFlowReturn QuicClientInitialSend(QUIC *);
static QuicFlowReturn QuicClientHandshakeRecv(QUIC *, RPacket *,
                                            QuicLPacketFlags);
static QuicFlowReturn QuicClientHandshakeSend(QUIC *);

static QuicStatemFlow client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .recv = QuicClientInitialRecv,
        .send = QuicClientInitialSend,
    },
    [QUIC_STATEM_HANDSHAKE] = {
        .recv = QuicClientHandshakeRecv,
        .send = QuicClientHandshakeSend,
    },
};

static QuicFlowReturn QuicClientInitialSend(QUIC *quic)
{
    QuicFlowReturn ret;

    ret = QuicInitialSend(quic);
    QuicBufReserve(QUIC_TLS_BUFFER(quic));
    return ret;
}

static QuicFlowReturn
QuicClientInitialRecv(QUIC *quic, RPacket *pkt, QuicLPacketFlags flags)
{
    QuicFlowReturn ret;

    ret = QuicInitialRecv(quic, pkt, flags);
    printf("server init, ret = %d\n", ret);
    if (ret == QUIC_FLOW_RET_ERROR) {
        return ret;
    }

    quic->statem.state = QUIC_STATEM_HANDSHAKE;

    return QUIC_FLOW_RET_WANT_READ;
}

static QuicFlowReturn QuicClientHandshakeSend(QUIC *quic)
{
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn
QuicClientHandshakeRecv(QUIC *quic, RPacket *pkt, QuicLPacketFlags flags)
{
    QuicFlowReturn ret;

    ret = QuicHandshakeRecv(quic, pkt, flags);
    printf("handshake recv\n");
    return ret;
}


int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_NELEM(client_statem));
}

