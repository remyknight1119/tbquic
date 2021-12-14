/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "common.h"
#include "tls_cipher.h"
#include "extension.h"
#include "log.h"

static QuicFlowReturn QuicTlsClientHelloBuild(QUIC_TLS *, void *);
static QuicFlowReturn QuicTlsServerHelloProc(QUIC_TLS *, void *);

static const QuicTlsProcess client_proc[HANDSHAKE_MAX] = {
    [QUIC_TLS_ST_OK] = {
        .flow_state = QUIC_FLOW_NOTHING,
        .next_state = QUIC_TLS_ST_CW_CLIENT_HELLO,
    },
    [QUIC_TLS_ST_CW_CLIENT_HELLO] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = QUIC_TLS_ST_CR_SERVER_HELLO,
        .handshake_type = CLIENT_HELLO,
        .handler = QuicTlsClientHelloBuild,
    },
    [QUIC_TLS_ST_CR_SERVER_HELLO] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = QUIC_TLS_ST_SW_SERVER_HELLO,
        .handshake_type = SERVER_HELLO,
        .handler = QuicTlsServerHelloProc,
    },
};

QuicFlowReturn QuicTlsConnect(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return QuicTlsHandshake(tls, data, len, client_proc,
                            QUIC_NELEM(client_proc));
}

static QuicFlowReturn QuicTlsClientHelloBuild(QUIC_TLS *tls, void *packet)
{
    WPacket *pkt = packet;

    if (WPacketPut2(pkt, TLS_VERSION_1_2) < 0) {
        QUIC_LOG("Put leagacy version failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicTlsGenRandom(tls->client_random, sizeof(tls->client_random),
                            pkt) < 0) {
        QUIC_LOG("Generate Client Random failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicTlsPutCipherList(tls, pkt) < 0) {
        QUIC_LOG("Put cipher list failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, 1) < 0) {
        QUIC_LOG("Put compression len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicTlsPutCompressionMethod(pkt) < 0) {
        QUIC_LOG("Put compression method failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsClientConstructExtensions(tls, pkt, TLSEXT_CLIENT_HELLO,
                                        NULL, 0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    printf("TTTTTTTTTTTls client hello build\n");
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn QuicTlsServerHelloProc(QUIC_TLS *tls, void *packet)
{
    RPacket *pkt = packet;
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *server_cipher = NULL;
    HLIST_HEAD(cipher_list);
    QuicFlowReturn ret = QUIC_FLOW_RET_WANT_READ;//QUIC_FLOW_RET_FINISH;
    uint16_t id = 0;

    ret = QuicTlsHelloHeadParse(tls, pkt, tls->server_random,
                sizeof(tls->server_random));
    if (ret != QUIC_FLOW_RET_FINISH) {
        return ret;
    }

    if (QuicTlsParseCipherList(&cipher_list, pkt, 2) < 0) {
        QUIC_LOG("Parse cipher list failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    /* Get the only one cipher member */
    hlist_for_each_entry(server_cipher, &cipher_list, node) {
        assert(server_cipher->cipher != NULL);
        id = server_cipher->cipher->id;
        break;
    }

    QuicTlsDestroyCipherList(&cipher_list);

    if (id == 0) {
        QUIC_LOG("Get server cipher failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    cipher = QuicTlsCipherMatchListById(&tls->cipher_list, id);
    if (cipher == NULL) {
        QUIC_LOG("Get shared cipher failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    /* Skip legacy Compression Method */
    if (RPacketPull(pkt, 1) < 0) {
        return QUIC_FLOW_RET_WANT_READ;
    }

    QUIC_LOG("TTTTTTTTTTTls server hello parse\n");
    return ret;
}

void QuicTlsClientInit(QUIC_TLS *tls)
{
    tls->handshake = QuicTlsConnect;
}
