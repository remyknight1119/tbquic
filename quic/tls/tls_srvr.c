/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "common.h"

static int QuicTlsClientHelloProcess(QUIC_TLS *, void *);

static const QuicTlsProcess server_proc[HANDSHAKE_MAX] = {
    [QUIC_TLS_ST_OK] = {
        .rwstate = QUIC_NOTHING,
        .next_state = QUIC_TLS_ST_SR_CLIENT_HELLO,
    },
    [QUIC_TLS_ST_SR_CLIENT_HELLO] = {
        .rwstate = QUIC_READING,
        .next_state = QUIC_TLS_ST_SW_SERVER_HELLO,
        .handshake_type = CLIENT_HELLO,
        .handler = QuicTlsClientHelloProcess,
    },
    [QUIC_TLS_ST_SW_SERVER_HELLO] = {
        .rwstate = QUIC_WRITING,
        .next_state = QUIC_TLS_ST_SW_SERVER_CERTIFICATE,
    },
};

#define QUIC_TLS_SERVER_PROC_NUM QUIC_ARRAY_SIZE(server_proc)

int QuicTlsAccept(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return QuicTlsHandshake(tls, data, len, server_proc,
                            QUIC_TLS_SERVER_PROC_NUM);
}

static int QuicTlsClientHelloProcess(QUIC_TLS *tls, void *packet)
{
    RPacket *pkt = packet;
    RPacket msg = {};
    uint32_t len = 0;
    uint32_t legacy_version = 0;

    if (RPacketGet3(pkt, &len) < 0) {
        return -1;
    }

    if (RPacketTransfer(&msg, pkt, len) < 0) {
        return -1;
    }

    if (RPacketGet2(&msg, &legacy_version) < 0) {
        return -1;
    }

    if (RPacketCopyBytes(&msg, tls->client_random,
                sizeof(tls->client_random)) < 0) {
        return -1;
    }

    printf("len = %x, version = %x\n", len, legacy_version);
    return 0;
}

int QuicTlsServerInit(QUIC_TLS *tls)
{
    tls->handshake = QuicTlsAccept;
    tls->server = 1;

    return QuicTlsInit(tls);
}
