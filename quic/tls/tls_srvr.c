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
#include "format.h"
#include "log.h"

static QuicFlowReturn TlsClientHelloProc(TLS *, void *);
static QuicFlowReturn TlsSrvrCertProc(TLS *, void *);
static QuicFlowReturn TlsSrvrCertVerifyProc(TLS *, void *);
static QuicFlowReturn TlsSrvrFinishedProc(TLS *, void *);
static QuicFlowReturn TlsServerHelloBuild(TLS *, void *);
static QuicFlowReturn TlsSrvrEncryptedExtBuild(TLS *, void *);
static QuicFlowReturn TlsSrvrCertRequestBuild(TLS *, void *);
static QuicFlowReturn TlsSrvrServerCertBuild(TLS *, void *);
static QuicFlowReturn TlsSrvrCertVerifyBuild(TLS *, void *);
static QuicFlowReturn TlsSrvrFinishedBuild(TLS *, void *);
static QuicFlowReturn TlsSrvrNewSessionTicketBuild(TLS *, void *);
static int TlsSrvrClientHelloPostWork(TLS *);
static int TlsSrvrServerHelloPostWork(TLS *);
static int TlsServerWriteFinishedPostWork(TLS *);
static int TlsServerReadFinishedPostWork(TLS *);

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
        .post_work = TlsSrvrClientHelloPostWork,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [TLS_ST_SW_SERVER_HELLO] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_ENCRYPTED_EXTENSIONS,
        .msg_type = TLS_MT_SERVER_HELLO,
        .handler = TlsServerHelloBuild,
        .post_work = TlsSrvrServerHelloPostWork,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [TLS_ST_SW_ENCRYPTED_EXTENSIONS] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_SERVER_CERTIFICATE,
        .msg_type = TLS_MT_ENCRYPTED_EXTENSIONS,
        .handler = TlsSrvrEncryptedExtBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SW_CERT_REQUEST] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_SERVER_CERTIFICATE,
        .msg_type = TLS_MT_CERTIFICATE_REQUEST,
        .handler = TlsSrvrCertRequestBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SW_SERVER_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_CERT_VERIFY,
        .msg_type = TLS_MT_CERTIFICATE,
        .handler = TlsSrvrServerCertBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SW_CERT_VERIFY] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_FINISHED,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handler = TlsSrvrCertVerifyBuild,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SW_FINISHED] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SR_FINISHED,
        .msg_type = TLS_MT_FINISHED,
        .handler = TlsSrvrFinishedBuild,
        .post_work = TlsServerWriteFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SR_CLIENT_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_SR_CERT_VERIFY,
        .msg_type = TLS_MT_CERTIFICATE,
        .handler = TlsSrvrCertProc,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SR_CERT_VERIFY] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_SR_FINISHED,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handler = TlsSrvrCertVerifyProc,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SR_FINISHED] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_HANDSHAKE_DONE,
        .msg_type = TLS_MT_FINISHED,
        .handler = TlsSrvrFinishedProc,
        .post_work = TlsServerReadFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SW_NEW_SESSION_TICKET] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_HANDSHAKE_DONE,
        .msg_type = TLS_MT_NEW_SESSION_TICKET,
        .handler = TlsSrvrNewSessionTicketBuild,
        .pkt_type = QUIC_PKT_TYPE_1RTT,
    },
    [TLS_ST_HANDSHAKE_DONE] = {
        .flow_state = QUIC_FLOW_FINISHED,
        .next_state = TLS_ST_HANDSHAKE_DONE,
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

static QuicFlowReturn TlsSrvrCertProc(TLS *s, void *packet)
{
    QUIC_LOG("In\n");
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn TlsSrvrCertVerifyProc(TLS *s, void *packet)
{
    QUIC_LOG("In\n");
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn TlsSrvrFinishedProc(TLS *s, void *packet)
{
    RPacket *pkt = packet;
    QUIC *quic = QuicTlsTrans(s);

    if (TlsFinishedCheck(s, pkt) < 0) {
        QUIC_LOG("Finished check failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicCreateAppDataClientDecoders(quic) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    QUIC_LOG("Finished\n");
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
        QUIC_LOG("Generate Srvr Random failed\n");
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

    return QUIC_FLOW_RET_NEXT;
}

static QuicFlowReturn TlsSrvrEncryptedExtBuild(TLS *s, void *packet)
{
    if (TlsSrvrConstructExtensions(s, packet, TLSEXT_ENCRYPTED_EXT, NULL,
                0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn TlsSrvrCertRequestBuild(TLS *s, void *packet)
{
    return QUIC_FLOW_RET_FINISH;
}

static QuicFlowReturn TlsSrvrServerCertBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;
    QuicCertPkey *cpk = s->tmp.cert;

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return TlsCertChainBuild(s, pkt, cpk, TlsSrvrConstructExtensions);
}

static QuicFlowReturn TlsSrvrCertVerifyBuild(TLS *s, void *packet)
{
    return TlsCertVerifyBuild(s, packet);
}

static QuicFlowReturn TlsSrvrFinishedBuild(TLS *s, void *packet)
{
    if (TlsFinishedBuild(s, packet) == QUIC_FLOW_RET_ERROR) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_NEXT;
}

static QuicFlowReturn TlsSrvrNewSessionTicketBuild(TLS *s, void *packet)
{
    return QUIC_FLOW_RET_FINISH;
}

static int TlsSrvrServerHelloPostWork(TLS *s)
{
    QUIC *quic = QuicTlsTrans(s);

    if (QuicCreateHandshakeServerEncoders(quic) < 0) {
        return -1;
    }

    return 0;
}

static int TlsEarlyPostProcessClientHello(TLS *s)
{
    if (TlsSetServerSigAlgs(s) < 0) {
        return -1;
    }

    return 0;
}

static int TlsSrvrClientHelloPostWork(TLS *s)
{
    QUIC *quic = QuicTlsTrans(s);
    
    if (TlsEarlyPostProcessClientHello(s) < 0) {
        return -1;
    }

    if (TlsChooseSigalg(s) < 0) {
        return -1;
    }

    if (QuicStreamInit(quic) < 0) {
        return -1;
    }

    return 0;
}

static int TlsServerWriteFinishedPostWork(TLS *s)
{
    QUIC *quic = QuicTlsTrans(s);
    size_t secret_size = 0;

    if (TlsGenerateMasterSecret(s, s->master_secret, s->handshake_secret,
                                    &secret_size) < 0) {
        return -1;
    }

    if (QuicCreateHandshakeClientDecoders(quic) < 0) {
        return -1;
    }

    return QuicCreateAppDataServerEncoders(quic);
}

static int TlsServerReadFinishedPostWork(TLS *s)
{
    return 0;
}

