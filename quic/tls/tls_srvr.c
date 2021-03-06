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
#include "asn1.h"
#include "log.h"

#define TLS_NEW_SESS_TICKET_NUM     2

QuicFlowReturn TlsClientHelloProc(TLS *s, void *packet)
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

QuicFlowReturn TlsSrvrCertProc(TLS *s, void *packet)
{
    QUIC *quic = QuicTlsTrans(s);
    STACK_OF(X509) *sk = NULL;
    RPacket *pkt = packet;
    X509 *x = NULL;
    const uint8_t *certbytes = NULL;
    const uint8_t *certstart = NULL;
    RPacket spkt = {};
    RPacket context = {};
    RPacket extension = {};
    uint32_t len = 0;
    size_t chainidx = 0;
    int v = 0;

    if ((sk = sk_X509_new_null()) == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGetLengthPrefixed1(pkt, &context) < 0) {
        goto err;
    }

    //s->pha_context
    if (RPacketGetLengthPrefixed3(pkt, &spkt) < 0) {
        goto err;
    }

    if (RPacketRemaining(pkt) != 0) {
        goto err;
    }

    for (chainidx = 0; RPacketRemaining(&spkt) > 0; chainidx++) {
        if (RPacketGet3(&spkt, &len) < 0) {
            goto err;
        }

        if (RPacketGetBytes(&spkt, &certbytes, len) < 0) {
            goto err;
        }

        certstart = certbytes;
        x = d2i_X509(NULL, (const unsigned char **)&certbytes, len);
        if (x == NULL) {
            QUIC_LOG("d2i_X509 failed\n");
            goto err;
        }

        if (certbytes != (certstart + len)) {
            QUIC_LOG("certbytes not match(%p, %p)\n", certbytes,
                        certstart + len);
            goto err;
        }

        if (RPacketGetLengthPrefixed2(&spkt, &extension) < 0) {
            goto err;
        }

        if (TlsSrvrParseExtensions(s, &extension, TLSEXT_CERTIFICATE,
                    NULL, 0) < 0) {
            goto err;
        }

        if (!sk_X509_push(sk, x)) {
            goto err;
        }

        x = NULL;
    }

    if (sk_X509_num(sk) <= 0) {
        if (quic->verify_mode != QUIC_TLS_VERIFY_NONE) {
            goto err;
        }
    } else {
        v = QuicVerifyCertChain(quic, sk);
        if (quic->verify_mode != QUIC_TLS_VERIFY_NONE && v < 0) {
            goto err;
        }

        if (TlsSavePeerCert(s, sk) < 0) {
            goto err;
        }
    }

    if (TlsHandshakeHash(s, s->cert_verify_hash, sizeof(s->cert_verify_hash),
                &s->cert_verify_hash_len) < 0) {
        goto err;
    }

    return QUIC_FLOW_RET_FINISH;

err:
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return QUIC_FLOW_RET_ERROR;
}

QuicFlowReturn TlsSrvrFinishedProc(TLS *s, void *packet)
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

QuicFlowReturn TlsServerHelloBuild(TLS *s, void *packet)
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

QuicFlowReturn TlsSrvrEncryptedExtBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;

    if (TlsSrvrConstructExtensions(s, pkt, TLSEXT_ENCRYPTED_EXT, NULL, 0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (s->hit) {
        QUIC_TLS_STATE_SET(s, QUIC_STATEM_TLS_ST_SW_FINISHED);
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsSrvrCertRequestBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;

    if (WPacketPut1(pkt, 0) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsSrvrConstructExtensions(s, pkt, TLSEXT_CERTIFICATE_REQUEST,
                NULL, 0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    s->cert_req = 1;
    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsSrvrServerCertBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;
    QuicCertPkey *cpk = s->tmp.cert;

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return TlsCertChainBuild(s, pkt, cpk, TlsSrvrConstructExtensions);
}

QuicFlowReturn TlsSrvrCertVerifyBuild(TLS *s, void *packet)
{
    return TlsCertVerifyBuild(s, packet);
}

QuicFlowReturn TlsSrvrFinishedBuild(TLS *s, void *packet)
{
    if (TlsFinishedBuild(s, packet) == QUIC_FLOW_RET_ERROR) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_NEXT;
}

#ifdef QUIC_TEST
uint8_t *(*QuicSessionTicketTest)(uint8_t *senc, int *slen);
int (*QuicSessionTicketIvTest)(uint8_t *iv);
#else
static
#endif
int TlsConstructStatelessTicket(TLS *s, QUIC_SESSION *sess,
        WPacket *pkt, RPacket *tick_nonce)
{
    EVP_CIPHER_CTX *ctx = NULL;
    HMAC_CTX *hctx = NULL;
    QuicSessionTicket *t = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    TlsTicketKey *tk = &s->ext.ticket_key;
    uint8_t *encdata1 = NULL;
    uint8_t *encdata2 = NULL;
    uint8_t *macdata1 = NULL;
    uint8_t *macdata2 = NULL;
    uint8_t *senc = NULL;
    uint8_t *p = NULL;
    uint8_t *tkhead = NULL;
    uint8_t iv[EVP_MAX_IV_LENGTH] = {};
    uint8_t key_name[TLSEXT_KEYNAME_LENGTH] = {};
    unsigned int hlen = 0;
    size_t macoffset = 0;
    size_t macendoffset = 0;
    int slen = 0;
    int len = 0;
    int lenfinal = 0;
    int iv_len = 0;
    int err = -1;

    t = QuicSessionTicketPickTail(sess);
    if (t == NULL) {
        goto err;
    }

    slen = i2dQuicSession(sess, NULL);
    if (slen <= 0) {
        goto err;
    }

    senc = QuicMemMalloc(slen);
    if (senc == NULL) {
        goto err;
    }

    p = senc;
    if (i2dQuicSession(sess, &p) <= 0) {
        goto err;
    }

#ifdef QUIC_TEST
    if (QuicSessionTicketTest != NULL) {
        senc = QuicSessionTicketTest(senc, &slen);
    }
#endif
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

#ifdef QUIC_TEST
    if (QuicSessionTicketIvTest != NULL) {
        iv_len = QuicSessionTicketIvTest(iv);
    }
#endif
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

    macoffset = WPacket_get_written(pkt);
    if (WPacketMemcpy(pkt, key_name, sizeof(key_name)) < 0) {
        goto err;
    }

    if (WPacketMemcpy(pkt, iv, iv_len) < 0) {
        goto err;
    }

    if (WPacketReserveBytes(pkt, slen + EVP_MAX_BLOCK_LENGTH, &encdata1) < 0) {
        goto err;
    }

    if (EVP_EncryptUpdate(ctx, encdata1, &len, senc, slen) == 0) {
        goto err;
    }

    if (WPacketAllocateBytes(pkt, len, &encdata2) < 0) {
        goto err;
    }

    if (encdata1 != encdata2) {
        goto err;
    }

    if (EVP_EncryptFinal(ctx, encdata1 + len, &lenfinal) == 0) {
        goto err;
    }

    if (WPacketAllocateBytes(pkt, lenfinal, &encdata2) < 0) {
        goto err;
    }

    if (encdata1 + len != encdata2) {
        goto err;
    }

    if (len + lenfinal > slen + EVP_MAX_BLOCK_LENGTH) {
        goto err;
    }

    tkhead = WPacket_get_data(pkt, macoffset);
    macendoffset = WPacket_get_written(pkt);

    assert(QUIC_GT(macendoffset, macoffset));
    if (HMAC_Update(hctx, tkhead, macendoffset - macoffset) == 0) {
        goto err;
    }

    if (WPacketReserveBytes(pkt, EVP_MAX_MD_SIZE, &macdata1) < 0) {
        goto err;
    }

    if (HMAC_Final(hctx, macdata1, &hlen) == 0) {
        goto err;
    }

    if (hlen > EVP_MAX_MD_SIZE) {
        goto err;
    }

    if (WPacketAllocateBytes(pkt, hlen, &macdata2) < 0) {
        goto err;
    }

    if (macdata1 != macdata2) {
        goto err;
    }

    if (WPacketClose(pkt) < 0) {
        goto err;
    }

    err = 0;
err:
    QuicMemFree(senc);
    HMAC_CTX_free(hctx);
    EVP_CIPHER_CTX_free(ctx);
    return err;
}

QuicFlowReturn TlsSrvrNewSessionTicketBuild(TLS *s, void *packet)
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

    QUIC_LOG("Build\n");
    sess = TlsGetSession(s);
    if (sess == NULL) {
        goto err;
    }

    if (RAND_bytes(age_add_u.age_add_c, sizeof(age_add_u)) <= 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RAND_bytes(ticket, sizeof(ticket)) <= 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    age_add = age_add_u.age_add;
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

    QuicSessionTicketAdd(sess, t);
    t = NULL;
    if (TlsConstructStatelessTicket(s, sess, pkt, &tnonce) < 0) {
        goto err;
    }

    if (TlsSrvrConstructExtensions(s, pkt, TLSEXT_NEW_SESSION_TICKET,
                NULL, 0) < 0) {
        goto err;
    }

    ret = QUIC_FLOW_RET_FINISH;
    s->next_ticket_nonce++;

err:
    QuicSessionTicketFree(t);
    if (s->next_ticket_nonce >= TLS_NEW_SESS_TICKET_NUM) {
        QUIC_TLS_STATE_SET(s, QUIC_STATEM_TLS_ST_SW_HANDSHAKE_DONE);
    }
    return ret;
}

static int TlsEarlyPostProcessClientHello(TLS *s)
{
    if (TlsSetServerSigAlgs(s) < 0) {
        return -1;
    }

    return 0;
}

int TlsSrvrClientHelloPostWork(QUIC *quic)
{
    TLS *s = &quic->tls;
    
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

int TlsSrvrSkipCheckCertRequest(TLS *s)
{
    QUIC *quic = QuicTlsTrans(s);

    if (s->hit) {
        return 0;
    }

    if (quic->verify_mode == QUIC_TLS_VERIFY_PEER) {
        return -1;
    }

    return 0;
}

int TlsSrvrSkipCheckClientCert(TLS *s)
{
    if (s->cert_req) {
        return -1;
    }

    return 0;
}

int TlsSrvrSkipCheckClientCertVerify(TLS *s)
{
    if (s->cert_req) {
        return -1;
    }

    return 0;
}

