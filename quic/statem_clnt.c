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

static QuicFlowReturn QuicClientInitialRecv(QUIC *, void *);
static QuicFlowReturn QuicClientInitialSend(QUIC *, void *);
static QuicFlowReturn QuicClientHandshakeRecv(QUIC *, void *);
static QuicFlowReturn QuicClientHandshakeSend(QUIC *, void *);

static QuicStateMachineFlow client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_INITIAL] = {
        .recv = QuicClientInitialRecv,
        .send = QuicClientInitialSend,
    },
    [QUIC_STATEM_HANDSHAKE] = {
        .recv = QuicClientHandshakeRecv,
        .send = QuicClientHandshakeSend,
    },
};

static QuicFlowReturn QuicClientInitialSend(QUIC *quic, void *packet)
{
    return QuicInitialSend(quic, packet);
}

static QuicFlowReturn QuicClientInitialRecv(QUIC *quic, void *packet)
{
    QuicFlowReturn ret;

    ret = QuicInitialRecv(quic, packet);
    printf("server init, ret = %d\n", ret);
    if (ret != QUIC_FLOW_RET_ERROR) {
        quic->statem.state = QUIC_STATEM_HANDSHAKE;
    }

    return ret;
}

static QuicFlowReturn QuicClientHandshakeRecv(QUIC *quic, void *packet)
{
    QuicFlowReturn ret;

    ret = QuicHandshakeRecv(quic, packet);
    printf("handshake recv\n");
    return ret;
}

static QuicFlowReturn QuicClientHandshakeSend(QUIC *quic, void *packet)
{
    return QUIC_FLOW_RET_WANT_READ;
}

int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_NELEM(client_statem));
}

