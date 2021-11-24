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

static int QuicClientInitialSend(QUIC *);
static QuicStateMachine client_statem[QUIC_STATEM_MAX] = {
    [QUIC_STATEM_READY] = {
        .write = QuicClientInitialSend,
    },
};

#define QUIC_CLIENT_STATEM_NUM QUIC_ARRAY_SIZE(client_statem)

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

static int QuicClientInitialSend(QUIC *quic)
{
    QUIC_DATA *cid = NULL;
    QUIC_BUFFER *rbuffer = NULL;
    QUIC_BUFFER *wbuffer = NULL;
    WPacket pkt = {};

    cid = &quic->dcid;
    if (cid->data == NULL && QuicCidGen(cid, QUIC_MAX_CID_LENGTH) < 0) {
        return -1;
    }

    if (QuicCreateInitialDecoders(quic, quic->version) < 0) {
        return -1;
    }

    rbuffer = &quic->rbuffer;
    if (QuicTlsDoHandshake(&quic->tls, QuicBufData(rbuffer),
                QuicBufDataLength(rbuffer)) < 0) {
        QUIC_LOG("TLS handshake failed\n");
        return -1;
    }

    if (QuicInitialFrameBuild(quic) < 0) {
        QUIC_LOG("Initial frame build failed\n");
        return -1;
    }

    wbuffer = &quic->wbuffer;
    WPacketBufInit(&pkt, wbuffer->buf);

    if (QuicInitialPacketGen(quic, &pkt) < 0) {
        WPacketCleanup(&pkt);
        return -1;
    }

    wbuffer->data_len = WPacket_get_written(&pkt);
    WPacketCleanup(&pkt);

    if (QuicDatagramSend(quic) < 0) {
        QUIC_LOG("Send failed\n");
        return -1;
    }

    quic->statem = QUIC_STATEM_INITIAL_SENT;
    printf("client init\n");
    return 0;
}

int QuicConnect(QUIC *quic)
{
    return QuicStateMachineAct(quic, client_statem, QUIC_CLIENT_STATEM_NUM);
}

