/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/rand.h>

#include "quic_local.h"
#include "packet_format.h"
#include "common.h"
#include "datagram.h"
#include "mem.h"
#include "rand.h"
#include "log.h"

static QuicFlowReturn QuicClientInitialSend(QUIC *, void *);
static QuicFlowReturn QuicClientInitialRecv(QUIC *, void *);

static QuicStateMachine client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_READY] = {
        .flow_state = QUIC_FLOW_NOTHING, 
        .next_state = QUIC_STATEM_INITIAL_SEND,
    },
    [QUIC_STATEM_INITIAL_SEND] = {
        .flow_state = QUIC_FLOW_WRITING, 
        .next_state = QUIC_STATEM_INITIAL_RECV,
        .handler = QuicClientInitialSend,
    },
    [QUIC_STATEM_INITIAL_RECV] = {
        .flow_state = QUIC_FLOW_READING, 
        .next_state = QUIC_STATEM_HANDSHAKE_SEND,
        .handler = QuicClientInitialRecv,
    },
};

static int QuicCidGen(QUIC_DATA *cid, size_t len)
{
    assert(cid->data == NULL);

    cid->data = QuicMemMalloc(len);
    if (cid->data == NULL) {
        return -1;
    }

    QuicRandBytes(cid->data, len);
    cid->len = len;

    return 0;
}

static QuicFlowReturn QuicClientInitialSend(QUIC *quic, void *packet)
{
    QUIC_DATA *cid = NULL;
    WPacket *pkt = packet;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, QUIC_MAX_CID_LENGTH) < 0) {
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

    printf("client init\n");
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn QuicClientInitialRecv(QUIC *quic, void *packet)
{
    printf("server init\n");
    return QUIC_FLOW_RET_WANT_READ;
}

int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_NELEM(client_statem));
}

