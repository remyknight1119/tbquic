/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "common.h"
#include "log.h"

static QuicFlowReturn QuicTlsClientHelloProc(QUIC_TLS *, void *);
static QuicFlowReturn QuicTlsServerHelloBuild(QUIC_TLS *, void *);

static const QuicTlsProcess server_proc[HANDSHAKE_MAX] = {
    [QUIC_TLS_ST_OK] = {
        .flow_state = QUIC_FLOW_NOTHING,
        .next_state = QUIC_TLS_ST_SR_CLIENT_HELLO,
    },
    [QUIC_TLS_ST_SR_CLIENT_HELLO] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = QUIC_TLS_ST_SW_SERVER_HELLO,
        .handshake_type = CLIENT_HELLO,
        .handler = QuicTlsClientHelloProc,
    },
    [QUIC_TLS_ST_SW_SERVER_HELLO] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = QUIC_TLS_ST_SW_SERVER_CERTIFICATE,
        .handshake_type = SERVER_HELLO,
        .handler = QuicTlsServerHelloBuild,
    },
};

#define QUIC_TLS_SERVER_PROC_NUM QUIC_NELEM(server_proc)

QuicFlowReturn QuicTlsAccept(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return QuicTlsHandshake(tls, data, len, server_proc,
                            QUIC_TLS_SERVER_PROC_NUM);
}

static QuicFlowReturn QuicTlsClientHelloProc(QUIC_TLS *tls, void *packet)
{
    RPacket *pkt = packet;
    RPacket msg = {};
    uint32_t len = 0;
    uint32_t legacy_version = 0;

    if (RPacketGet3(pkt, &len) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (RPacketTransfer(&msg, pkt, len) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (RPacketGet2(&msg, &legacy_version) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (RPacketCopyBytes(&msg, tls->client_random,
                sizeof(tls->client_random)) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    printf("len = %x, version = %x\n", len, legacy_version);
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn QuicTlsServerHelloBuild(QUIC_TLS *tls, void *packet)
{
    return QUIC_FLOW_RET_ERROR;
}

int QuicTlsServerInit(QUIC_TLS *tls, QUIC_CTX *ctx)
{
    tls->handshake = QuicTlsAccept;
    tls->server = 1;

    return QuicTlsInit(tls, ctx);
}
