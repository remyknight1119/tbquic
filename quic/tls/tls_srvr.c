/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "extension.h"
#include "quic_local.h"
#include "packet_local.h"
#include "tls_cipher.h"
#include "tls_lib.h"
#include "common.h"
#include "format.h"
#include "mem.h"
#include "session.h"
#include "log.h"

#define TICKET_NONCE_SIZE       8

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
        .next_state = TLS_ST_SW_NEW_SESSION_TICKET,
        .msg_type = TLS_MT_FINISHED,
        .handler = TlsSrvrFinishedProc,
        .post_work = TlsServerReadFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_SW_NEW_SESSION_TICKET] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_SW_NEW_SESSION_TICKET,
        .msg_type = TLS_MT_NEW_SESSION_TICKET,
        .handler = TlsSrvrNewSessionTicketBuild,
        .pkt_type = QUIC_PKT_TYPE_1RTT,
    },
    [TLS_ST_SW_HANDSHAKE_DONE] = {
        .flow_state = QUIC_FLOW_FINISHED,
        .next_state = TLS_ST_HANDSHAKE_DONE,
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

    if (QuicGetSession(QuicTlsTrans(s)) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

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

static int TlsConstructStatelessTicket(TLS *s, WPacket *pkt, uint32_t age_add,
       RPacket *tick_nonce, QuicSessionTicket *t)
{
    EVP_CIPHER_CTX *ctx = NULL;
    HMAC_CTX *hctx = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    TlsTicketKey *tk = &s->ext.ticket_key;
    uint8_t iv[EVP_MAX_IV_LENGTH] = {};
    uint8_t key_name[TLSEXT_KEYNAME_LENGTH] = {};
    int iv_len = 0;
    int err = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        goto err;
    }

    hctx = HMAC_CTX_new();
    if (hctx == NULL) {
        goto err;
    }

    iv_len = EVP_CIPHER_iv_length(cipher);
    if (RAND_bytes(iv, iv_len) <= 0) { 
        goto err;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, tk->tick_aes_key, iv)) {
        goto err;
    }

    if (!HMAC_Init_ex(hctx, tk->tick_hmac_key, sizeof(tk->tick_hmac_key),
                EVP_sha256(), NULL)) {
        goto err;
    }

    QuicMemcpy(key_name, tk->tick_key_name, sizeof(tk->tick_key_name));

    if (WPacketPut4(pkt, t->lifetime_hint) < 0) {
        goto err;
    }

    if (WPacketPut4(pkt, t->age_add) < 0) {
        goto err;
    }

    if (WPacketSubMemcpyU8(pkt, RPacketData(tick_nonce),
                RPacketRemaining(tick_nonce)) < 0) {
        goto err;
    }

    if (WPacketStartSubU16(pkt) < 0) {
        goto err;
    } 

    if (WPacketMemcpy(pkt, key_name, sizeof(key_name)) < 0) {
        goto err;
    }

    if (WPacketMemcpy(pkt, iv, iv_len) < 0) {
        goto err;
    }

    if (WPacketClose(pkt) < 0) {
        goto err;
    }

    err = 0;
err:
    HMAC_CTX_free(hctx);
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

static QuicFlowReturn TlsSrvrNewSessionTicketBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;
    QuicSessionTicket *t = NULL;
    QUIC_SESSION *sess = NULL;
    RPacket tnonce = {};
    union {
        uint8_t age_add_c[sizeof(uint32_t)];
        uint32_t age_add;
    } age_add_u;
    uint8_t ticket[QUIC_SESSION_TICKET_LEN] = {};
    uint8_t tick_nonce[TICKET_NONCE_SIZE] = {};
    uint64_t nonce = 0;
    uint32_t age_add = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;
    int i = 0;

    if (RAND_bytes(age_add_u.age_add_c, sizeof(age_add_u)) <= 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RAND_bytes(ticket, sizeof(ticket)) <= 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    age_add = age_add_u.age_add,
    t = QuicSessionTicketNew(s->lifetime_hint, age_add, ticket, sizeof(ticket));
    if (t == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    nonce = s->next_ticket_nonce;
    for (i = TICKET_NONCE_SIZE; i > 0; i--) {
        tick_nonce[i - 1] = (uint8_t)(nonce & 0xff);
        nonce >>= 8;
    }

    RPacketBufInit(&tnonce, tick_nonce, sizeof(tick_nonce));
    if (QuicSessionMasterKeyGen(s, t, &tnonce) < 0) {
        goto err;
    }

    if (TlsConstructStatelessTicket(s, pkt, age_add, &tnonce, t) < 0) {
        goto err;
    }

    if (TlsSrvrConstructExtensions(s, pkt, TLSEXT_NEW_SESSION_TICKET,
                NULL, 0) < 0) {
        goto err;
    }

    sess = TlsGetSession(s);
    if (sess == NULL) {
        goto err;
    }

    QuicSessionTicketAdd(sess, t);
    t = NULL;
    ret = QUIC_FLOW_RET_FINISH;
    s->next_ticket_nonce++;

err:
    QuicSessionTicketFree(t);
    QUIC_LOG("TTTTTTTTTTTTTTTTTTTTTTTTTTTTT\n");
    if (s->next_ticket_nonce >= 2) {
        s->handshake_state = TLS_ST_SW_HANDSHAKE_DONE;
    }
    return ret;
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

