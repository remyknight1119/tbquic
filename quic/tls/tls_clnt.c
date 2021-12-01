/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "common.h"
#include "tls_cipher.h"
#include "log.h"

static int QuicTlsClientHelloBuild(QUIC_TLS *, void *);

static const QuicTlsProcess client_proc[HANDSHAKE_MAX] = {
    [QUIC_TLS_ST_OK] = {
        .rwstate = QUIC_NOTHING,
        .next_state = QUIC_TLS_ST_CW_CLIENT_HELLO,
    },
    [QUIC_TLS_ST_CW_CLIENT_HELLO] = {
        .rwstate = QUIC_WRITING,
        .next_state = QUIC_TLS_ST_CR_SERVER_HELLO,
        .handler = QuicTlsClientHelloBuild,
        .handshake_type = CLIENT_HELLO,
    },
    [QUIC_TLS_ST_CR_SERVER_HELLO] = {
        .rwstate = QUIC_READING,
        .next_state = QUIC_TLS_ST_SW_SERVER_HELLO,
        .handshake_type = SERVER_HELLO,
    },
};

#define QUIC_TLS_CLIENT_PROC_NUM QUIC_NELEM(client_proc)

int QuicTlsConnect(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return QuicTlsHandshake(tls, data, len, client_proc,
                            QUIC_TLS_CLIENT_PROC_NUM);
}

static int QuicTlsClientHelloBuild(QUIC_TLS *tls, void *packet)
{
    WPacket *pkt = packet;

    if (WPacketPut2(pkt, TLS_VERSION_1_2) < 0) {
        QUIC_LOG("Put leagacy version failed\n");
        return -1;
    }

    if (QuicTlsGenRandom(tls->client_random, sizeof(tls->client_random),
                            pkt) < 0) {
        QUIC_LOG("Generate Client Random failed\n");
        return -1;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return -1;
    }

    if (QuicTlsPutCipherList(tls, pkt) < 0) {
        QUIC_LOG("Put cipher list failed\n");
        return -1;
    }

    if (WPacketPut1(pkt, 1) < 0) {
        QUIC_LOG("Put compression len failed\n");
        return -1;
    }

    if (QuicTlsPutCompressionMethod(pkt) < 0) {
        QUIC_LOG("Put compression method failed\n");
        return -1;
    }

    if (QuicTlsPutExtension(tls, pkt) < 0) {
        QUIC_LOG("Put extension failed\n");
        return -1;
    }

    printf("TTTTTTTTTTTls client hello build\n");
    return 0;
}

int QuicTlsClientInit(QUIC_TLS *tls)
{
    tls->handshake = QuicTlsConnect;
    tls->server = 0;

    return QuicTlsInit(tls);
}
