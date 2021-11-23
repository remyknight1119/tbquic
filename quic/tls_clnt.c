/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "rand.h"
#include "common.h"
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
    },
    [QUIC_TLS_ST_CR_SERVER_HELLO] = {
        .rwstate = QUIC_READING,
        .next_state = QUIC_TLS_ST_SW_SERVER_HELLO,
        .expect = SERVER_HELLO,
    },
};

#define QUIC_TLS_CLIENT_PROC_NUM QUIC_ARRAY_SIZE(client_proc)

int QuicTlsConnect(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return QuicTlsHandshake(tls, data, len, client_proc,
                            QUIC_TLS_CLIENT_PROC_NUM);
}

static int QuicTlsClientHelloBuild(QUIC_TLS *tls, void *packet)
{
    uint8_t *length = NULL;
    WPacket *pkt = packet;
    size_t msg_len = 0;

    if (WPacketPut1(pkt, CLIENT_HELLO) < 0) {
        QUIC_LOG("Put ClientHello message type failed\n");
        return -1;
    }

    if (WPacketAllocateBytes(pkt, TLS_HANDSHAKE_LEN_SIZE, &length) < 0) {
        return -1;
    }
    
    if (WPacketPut2(pkt, TLS_VERSION_1_2) < 0) {
        QUIC_LOG("Put leagacy version failed\n");
        return -1;
    }

    if (QuicRandBytes(tls->client_random, sizeof(tls->client_random)) < 0) {
        QUIC_LOG("Generate Client Random failed\n");
        return -1;
    }

    if (WPacketMemcpy(pkt, tls->client_random, sizeof(tls->client_random))
                        < 0) {
        QUIC_LOG("Copy Client Random failed\n");
        return -1;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return -1;
    }

    msg_len = WPacket_get_written(pkt) - TLS_HANDSHAKE_LEN_SIZE - 1;
    if (WPacketPutValue(length, msg_len, TLS_HANDSHAKE_LEN_SIZE) < 0){
        QUIC_LOG("Put length failed\n");
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
