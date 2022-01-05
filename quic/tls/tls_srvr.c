/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "extension.h"
#include "quic_local.h"
#include "packet_local.h"
#include "tls_cipher.h"
#include "tls_lib.h"
#include "common.h"
#include "log.h"

static QuicFlowReturn TlsClientHelloProc(TLS *, void *);
static QuicFlowReturn TlsServerHelloBuild(TLS *, void *);
static QuicFlowReturn TlsServerEncryptedExtBuild(TLS *, void *);

static const TlsProcess server_proc[TLS_MT_MESSAGE_TYPE_MAX] = {
    [TLS_ST_OK] = {
        .flow_state = QUIC_FLOW_NOTHING,
        .next_state = TLS_ST_SR_CLIENT_HELLO,
    },
    [TLS_ST_SR_CLIENT_HELLO] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_SW_SERVER_HELLO,
        .msg_type = TLS_MT_CLIENT_HELLO,
        .handler = TlsClientHelloProc,
    },
    [TLS_ST_SW_SERVER_HELLO] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_ENCRYPTED_EXTENSIONS,
        .msg_type = TLS_MT_SERVER_HELLO,
        .handler = TlsServerHelloBuild,
    },
    [TLS_ST_SW_ENCRYPTED_EXTENSIONS] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_SERVER_CERTIFICATE,
        .msg_type = TLS_MT_ENCRYPTED_EXTENSIONS,
        .handler = TlsServerEncryptedExtBuild,
    },
    [TLS_ST_SW_SERVER_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_FINISHED,
        //.flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_CERT_VERIFY,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
//        .handler = TlsServerEncryptedExtBuild,
    },
};

QuicFlowReturn TlsAccept(TLS *tls)
{
    return TlsHandshake(tls, server_proc, QUIC_NELEM(server_proc));
}

static QuicFlowReturn TlsClientHelloProc(TLS *s, void *packet)
{
    RPacket *pkt = packet;
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *server_cipher = NULL;
    HLIST_HEAD(cipher_list);
    uint32_t cipher_len = 0;
    uint32_t compress_len = 0;

    if (TlsHelloHeadParse(s, pkt, s->client_random,
                sizeof(s->client_random)) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet2(pkt, &cipher_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (cipher_len & 0x01) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketRemaining(pkt) < cipher_len) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsParseCipherList(&cipher_list, pkt, cipher_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    hlist_for_each_entry(server_cipher, &s->cipher_list, node) {
        assert(server_cipher->cipher != NULL);
        cipher = TlsCipherMatchListById(&cipher_list,
                server_cipher->cipher->id);
        if (cipher != NULL) {
            break;
        }
    }

    TlsDestroyCipherList(&cipher_list);
    if (cipher == NULL) {
        QUIC_LOG("No shared cipher found\n");
        return QUIC_FLOW_RET_ERROR;
    }

    s->handshake_cipher = cipher;
    /* Skip legacy Compression Method */
    if (RPacketGet1(pkt, &compress_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketPull(pkt, compress_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsSrvrParseExtensions(s, pkt, TLSEXT_CLIENT_HELLO, NULL, 0) < 0) {
        QUIC_LOG("Parse Extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    s->handshake_msg_len = RPacketTotalLen(pkt);
    if (TlsDigestCachedRecords(s) < 0) {
        QUIC_LOG("Digest cached records failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    s->handshake_msg_len = 0;
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn TlsServerHelloBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;

    if (WPacketPut2(pkt, TLS_VERSION_1_2) < 0) {
        QUIC_LOG("Put leagacy version failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsGenRandom(s->server_random, sizeof(s->server_random), pkt) < 0) {
        QUIC_LOG("Generate Server Random failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    assert(s->handshake_cipher != NULL);
    if (WPacketPut2(pkt, s->handshake_cipher->id) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put compression len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsSrvrConstructExtensions(s, pkt, TLSEXT_SERVER_HELLO, NULL, 0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    printf("SSSSSSSSSSSSSSSSSSSSSServerhello Build\n");
    return QUIC_FLOW_RET_STOP;
}

static QuicFlowReturn TlsServerEncryptedExtBuild(TLS *, void *)
{
    QUIC_LOG("Build\n");
    return QUIC_FLOW_RET_FINISH;
}
