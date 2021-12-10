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
    QUIC_DATA *cid = NULL;
    WPacket *pkt = packet;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, quic->cid_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    ret = QuicTlsDoHandshake(&quic->tls, NULL, 0);
    if (ret == QUIC_FLOW_RET_ERROR) {
        QUIC_LOG("TLS handshake failed\n");
        return ret;
    }

    if (QuicInitialFrameBuild(quic) < 0) {
        QUIC_LOG("Initial frame build failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicInitialPacketGen(quic, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    printf("client init, ret = %d\n", ret);
    return ret;
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
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn QuicClientHandshakeSend(QUIC *quic, void *packet)
{
    return QUIC_FLOW_RET_FINISH;
}

int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_NELEM(client_statem));
}

