/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "common.h"

static int QuicTlsClientHelloProcess(QUIC_TLS *, RPacket *);

static const QuicTlsProcess server_proc[HANDSHAKE_MAX] = {
    [CLIENT_HELLO] = {
        .next_type = CLIENT_KEY_EXCHANGE,
        .proc = QuicTlsClientHelloProcess,
    },
};

#define QUIC_TLS_SERVER_PROC_NUM QUIC_ARRAY_SIZE(server_proc)

int QuicTlsAccept(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    RPacket pkt = {};

    RPacketBufInit(&pkt, data, len);

    return QuicTlsDoProcess(tls, &pkt, server_proc, QUIC_TLS_SERVER_PROC_NUM);
}

static int QuicTlsClientHelloProcess(QUIC_TLS *tls, RPacket *pkt)
{
    printf("ClientHello\n");
 
    RPacketForward(pkt, RPacketRemaining(pkt));
    return 0;
}
