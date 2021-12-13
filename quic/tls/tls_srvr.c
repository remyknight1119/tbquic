/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "tls_cipher.h"
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
    HLIST_HEAD(cipher_list);
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;
    uint32_t cipher_len = 0;

    ret = QuicTlsHelloHeadParse(tls, pkt, tls->client_random,
                sizeof(tls->client_random));
    if (ret != QUIC_FLOW_RET_FINISH) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet2(pkt, &cipher_len) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (cipher_len & 0x01) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketRemaining(pkt) < cipher_len) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    if (QuicTlsParseCipherList(&cipher_list, pkt, cipher_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    QuicTlsDestroyCipherList(&cipher_list);

    return ret;
}

static QuicFlowReturn QuicTlsServerHelloBuild(QUIC_TLS *tls, void *packet)
{
    printf("SSSSSSSSSSSSSSSSSSSSSServerhello Build\n");
    return QUIC_FLOW_RET_ERROR;
}

void QuicTlsServerInit(QUIC_TLS *tls)
{
    tls->handshake = QuicTlsAccept;
}
