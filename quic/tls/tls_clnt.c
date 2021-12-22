/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>
#include <tbquic/cipher.h>

#include "packet_local.h"
#include "common.h"
#include "quic_local.h"
#include "tls_cipher.h"
#include "extension.h"
#include "log.h"

static int QuicTlsClientHelloBuild(QUIC_TLS *, void *);
static int QuicTlsServerHelloProc(QUIC_TLS *, void *);
static int QuicTlsEncExtProc(QUIC_TLS *, void *);
static int QuicTlsServerCertProc(QUIC_TLS *, void *);
static int QuicTlsCertVerifyProc(QUIC_TLS *, void *);
static int QuicTlsFinishedProc(QUIC_TLS *, void *);

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
        .next_state = QUIC_TLS_ST_CR_ENCRYPTED_EXTENSIONS,
        .handshake_type = SERVER_HELLO,
        .handler = QuicTlsServerHelloProc,
    },
    [QUIC_TLS_ST_CR_ENCRYPTED_EXTENSIONS] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = QUIC_TLS_ST_CR_SERVER_CERTIFICATE,
        .handshake_type = ENCRYPTED_EXTENSIONS,
        .handler = QuicTlsEncExtProc,
    },
    [QUIC_TLS_ST_CR_SERVER_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = QUIC_TLS_ST_CR_CERTIFICATE_VERIFY,
        .handshake_type = CERTIFICATE,
        .handler = QuicTlsServerCertProc,
    },
    [QUIC_TLS_ST_CR_CERTIFICATE_VERIFY] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = QUIC_TLS_ST_CR_FINISHED,
        .handshake_type = CERTIFICATE_VERIFY,
        .handler = QuicTlsCertVerifyProc,
    },
    [QUIC_TLS_ST_CR_FINISHED] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = QUIC_TLS_ST_CW_FINISHED,
        .handshake_type = FINISHED,
        .handler = QuicTlsFinishedProc,
    },
    [QUIC_TLS_ST_CW_FINISHED] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = QUIC_TLS_ST_HANDSHAKE_DONE,
        .handshake_type = FINISHED,
        .handler = QuicTlsFinishedBuild,
    },
    [QUIC_TLS_ST_HANDSHAKE_DONE] = {
        .flow_state = QUIC_FLOW_FINISHED,
    },
};

static QuicFlowReturn QuicTlsConnect(QUIC_TLS *tls)
{
    return QuicTlsHandshake(tls, client_proc, QUIC_NELEM(client_proc));
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

    if (TlsClientConstructExtensions(tls, pkt, TLSEXT_CLIENT_HELLO,
                                        NULL, 0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return -1;
    }

    return 0;
}

static int QuicTlsServerHelloProc(QUIC_TLS *tls, void *packet)
{
    QUIC *quic = QuicTlsTrans(tls);
    RPacket *pkt = packet;
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *server_cipher = NULL;
    HLIST_HEAD(cipher_list);
    uint16_t id = 0;

    if (QuicTlsHelloHeadParse(tls, pkt, tls->server_random,
                sizeof(tls->server_random)) < 0) {
        return -1;
    }

    if (QuicTlsParseCipherList(&cipher_list, pkt, 2) < 0) {
        QUIC_LOG("Parse cipher list failed\n");
        return -1;
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
        return -1;
    }

    cipher = QuicTlsCipherMatchListById(&tls->cipher_list, id);
    if (cipher == NULL) {
        QUIC_LOG("Get shared cipher failed\n");
        return -1;
    }

    tls->handshake_cipher = cipher;
    /* Skip legacy Compression Method */
    if (RPacketPull(pkt, 1) < 0) {
        return -1;
    }

    if (TlsClientParseExtensions(tls, pkt, TLSEXT_SERVER_HELLO, NULL, 0) < 0) {
        return -1;
    }

    //change cipher state
    if (QuicCreateHandshakeServerDecoders(quic) < 0) {
        return -1;
    }

    QuicBufClear(QUIC_TLS_BUFFER(quic));
    return 0;
}

static int QuicTlsEncExtProc(QUIC_TLS *tls, void *packet)
{
    QUIC_LOG("in\n");
    return TlsClientParseExtensions(tls, packet, TLSEXT_SERVER_HELLO, NULL, 0);
}

static int QuicTlsServerCertProc(QUIC_TLS *tls, void *packet)
{
    QUIC_LOG("in\n");
    return 0;
}

static int QuicTlsCertVerifyProc(QUIC_TLS *, void *)
{
    QUIC_LOG("in\n");
    return 0;
}

static int QuicTlsFinishedProc(QUIC_TLS *, void *)
{
    QUIC_LOG("in\n");
    return 0;
}

void QuicTlsClientInit(QUIC_TLS *tls)
{
    tls->handshake = QuicTlsConnect;
}
