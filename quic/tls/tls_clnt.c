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
#include "sig_alg.h"
#include "extension.h"
#include "tls_lib.h"
#include "mem.h"
#include "session.h"
#include "log.h"

static int TlsClntEncExtPostWork(TLS *);
static int TlsClntFinishedPostWork(TLS *);

const TlsProcess client_proc[TLS_MT_MESSAGE_TYPE_MAX] = {
    [TLS_ST_CR_ENCRYPTED_EXTENSIONS] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_CERT_REQUEST,
        .msg_type = TLS_MT_ENCRYPTED_EXTENSIONS,
        .handler = TlsClntEncExtProc,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
        .post_work = TlsClntEncExtPostWork,
    },
    [TLS_ST_CR_CERT_REQUEST] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_SERVER_CERTIFICATE,
        .msg_type = TLS_MT_CERTIFICATE_REQUEST,
        .handler = TlsCertRequestProc,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
        .skip_check = TlsClntSkipCheckCertRequest,
    },
    [TLS_ST_CR_SERVER_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_CERT_VERIFY,
        .msg_type = TLS_MT_CERTIFICATE,
        .handler = TlsServerCertProc,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
        .skip_check = TlsClntSkipCheckServerCert,
    },
    [TLS_ST_CR_CERT_VERIFY] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_FINISHED,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handler = TlsCertVerifyProc,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
        .skip_check = TlsClntSkipCheckCertVerify,
    },
    [TLS_ST_CR_FINISHED] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CW_FINISHED,
        .msg_type = TLS_MT_FINISHED,
        .handler = TlsClntFinishedProc,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [TLS_ST_CW_CLIENT_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_CW_CERT_VERIFY,
        .msg_type = TLS_MT_CERTIFICATE,
        .handler = TlsClntCertBuild,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [TLS_ST_CW_CERT_VERIFY] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_CW_FINISHED,
        .msg_type = TLS_MT_CERTIFICATE_VERIFY,
        .handler = TlsClntCertVerifyBuild,
        .pkt_type = QUIC_PKT_TYPE_INITIAL,
    },
    [TLS_ST_CW_FINISHED] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_CR_NEW_SESSION_TICKET,
        .msg_type = TLS_MT_FINISHED,
        .handler = TlsClntFinishedBuild,
        .post_work = TlsClntFinishedPostWork,
        .pkt_type = QUIC_PKT_TYPE_HANDSHAKE,
    },
    [TLS_ST_CR_NEW_SESSION_TICKET] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_NEW_SESSION_TICKET,
        .msg_type = TLS_MT_NEW_SESSION_TICKET,
        .handler = TlsClntNewSessionTicketProc,
        .pkt_type = QUIC_PKT_TYPE_1RTT,
    },
    [TLS_ST_HANDSHAKE_DONE] = {
        .flow_state = QUIC_FLOW_FINISHED,
        .next_state = TLS_ST_HANDSHAKE_DONE,
    },
};

QuicFlowReturn TlsClntHelloBuild(TLS *s, void *packet)
{
    WPacket *pkt = packet;

    if (WPacketPut2(pkt, TLS_VERSION_1_2) < 0) {
        QUIC_LOG("Put leagacy version failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsGenRandom(s->client_random, sizeof(s->client_random), pkt) < 0) {
        QUIC_LOG("Generate Client Random failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsPutCipherList(s, pkt) < 0) {
        QUIC_LOG("Put cipher list failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (WPacketPut1(pkt, 1) < 0) {
        QUIC_LOG("Put compression len failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsPutCompressionMethod(pkt) < 0) {
        QUIC_LOG("Put compression method failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsClntConstructExtensions(s, pkt, TLSEXT_CLIENT_HELLO, NULL, 0) < 0) {
        QUIC_LOG("Construct extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_NEXT;
}

QuicFlowReturn TlsClntCertBuild(TLS *s, void *packet)
{
    return QUIC_FLOW_RET_NEXT;
}

QuicFlowReturn TlsClntCertVerifyBuild(TLS *s, void *packet)
{
    return QUIC_FLOW_RET_NEXT;
}

QuicFlowReturn TlsClntFinishedBuild(TLS *s, void *packet)
{
    QuicFlowReturn ret = QUIC_FLOW_RET_ERROR;

    ret = TlsFinishedBuild(s, packet);
    if (ret == QUIC_FLOW_RET_ERROR) {
        return ret;
    }

    return QUIC_FLOW_RET_NEXT;
}

QuicFlowReturn TlsServerHelloProc(TLS *tls, void *packet)
{
    QUIC *quic = QuicTlsTrans(tls);
    RPacket *pkt = packet;
    const TlsCipher *cipher = NULL;
    TlsCipherListNode *server_cipher = NULL;
    HLIST_HEAD(cipher_list);
    uint16_t id = 0;

    if (TlsHelloHeadParse(tls, pkt, tls->server_random,
                sizeof(tls->server_random)) < 0) {
        QUIC_LOG("Parse Hello Head failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsParseCipherList(&cipher_list, pkt, 2) < 0) {
        QUIC_LOG("Parse cipher list failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    /* Get the only one cipher member */
    hlist_for_each_entry(server_cipher, &cipher_list, node) {
        assert(server_cipher->cipher != NULL);
        id = server_cipher->cipher->id;
        break;
    }

    TlsDestroyCipherList(&cipher_list);

    if (id == 0) {
        QUIC_LOG("Get server cipher failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    cipher = TlsCipherMatchListById(&tls->cipher_list, id);
    if (cipher == NULL) {
        QUIC_LOG("Get shared cipher failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    tls->handshake_cipher = cipher;
    /* Skip legacy Compression Method */
    if (RPacketPull(pkt, 1) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsClntParseExtensions(tls, pkt, TLSEXT_SERVER_HELLO, NULL, 0) < 0) {
        QUIC_LOG("Parse Extension failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    tls->handshake_msg_len = RPacketTotalLen(pkt);
    //change cipher state
    if (QuicCreateHandshakeServerDecoders(quic) < 0) {
        QUIC_LOG("Create Handshake Decoders failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    tls->handshake_msg_len = 0;
    QuicBufClear(&tls->buffer);

    if (QuicGetSession(quic) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsClntEncExtProc(TLS *tls, void *packet)
{
    if (TlsClntParseExtensions(tls, packet, TLSEXT_SERVER_HELLO, NULL, 0) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsCertRequestProc(TLS *tls, void *packet)
{
    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsServerCertProc(TLS *s, void *packet)
{
    QUIC *quic = QuicTlsTrans(s);
    RPacket *pkt = packet;
    const uint8_t *certbytes = NULL;
    const uint8_t *certstart = NULL;
    STACK_OF(X509) *sk = NULL;
    X509 *x = NULL;
    RPacket extensions = {};
    size_t chainidx = 0;
    uint32_t context = 0;
    uint32_t cert_list_len = 0;
    uint32_t cert_len = 0;
    int v = 0;
    QuicFlowReturn ret = QUIC_FLOW_RET_FINISH;

    if (RPacketGet1(pkt, &context) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet3(pkt, &cert_list_len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketRemaining(pkt) != cert_list_len) {
        return QUIC_FLOW_RET_ERROR;
    }

    if ((sk = sk_X509_new_null()) == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    for (chainidx = 0; RPacketRemaining(pkt); chainidx++) {
        if (RPacketGet3(pkt, &cert_len) < 0) {
            QUIC_LOG("Get cert len failed\n");
            goto out;
        }

        if (RPacketGetBytes(pkt, &certbytes, cert_len) < 0) {
            QUIC_LOG("Get bytes(%u) failed\n", cert_len);
            goto out;
        }

        certstart = certbytes;
        x = d2i_X509(NULL, (const unsigned char **)&certbytes, cert_len);
        if (x == NULL) {
            QUIC_LOG("Parse cert failed\n");
            goto out;
        }
        
        if (certbytes != (certstart + cert_len)) {
            QUIC_LOG("Cert bytes not match(b = %p, s = %p))\n",
                    certbytes, certstart + cert_len);
            goto out;
        }
        
        if (RPacketGetLengthPrefixed2(pkt, &extensions) < 0) {
            QUIC_LOG("Get cert extension failed\n");
            goto out;
        }
        
        if (RPacketRemaining(&extensions) && TlsClntParseExtensions(s,
                    &extensions, TLSEXT_CERTIFICATE, x, chainidx) < 0) {
            QUIC_LOG("Parse cert extension failed\n");
            goto out;
        }

        if (!sk_X509_push(sk, x)) {
            goto out;
        }
        x = NULL;
    }

    v = QuicVerifyCertChain(quic, sk);
    if (quic->verify_mode != QUIC_TLS_VERIFY_NONE && v < 0) {
        goto out;
    }

    x = sk_X509_value(sk, 0);
    if (x == NULL) {
        goto out;
    }
    X509_up_ref(x);
    X509_free(s->peer_cert);
    s->peer_cert = x;
    x = NULL;

    if (TlsHandshakeHash(s, s->cert_verify_hash, sizeof(s->cert_verify_hash),
                &s->cert_verify_hash_len) < 0) {
        goto out;
    }

    ret = QUIC_FLOW_RET_FINISH;
out:
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return ret;
}

QuicFlowReturn TlsCertVerifyProc(TLS *s, void *packet)
{
    RPacket *pkt = packet;
    EVP_PKEY *pkey = NULL;
    const EVP_MD *md = NULL;
    const uint8_t *data = NULL;
    uint32_t sigalg = 0;
    uint32_t len = 0;
    int pkey_size = 0;

    pkey = X509_get0_pubkey(s->peer_cert);
    if (pkey == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsLookupSigAlgByPkey(pkey) == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet2(pkt, &sigalg) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsCheckPeerSigAlg(s, sigalg, pkey) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    md = TlsLookupMd(s->peer_sigalg);
    if (md == NULL) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet2(pkt, &len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    pkey_size = EVP_PKEY_size(pkey);
    if (pkey_size != len) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGetBytes(pkt, &data, len) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsDoCertVerify(s, data, len, pkey, md) < 0) {
        QUIC_LOG("Verify Failed\n");
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsClntFinishedProc(TLS *s, void *packet)
{
    RPacket *pkt = packet;
    QUIC *quic = QuicTlsTrans(s);
    size_t secret_size = 0;

    if (TlsFinishedCheck(s, pkt) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (TlsGenerateMasterSecret(s, s->master_secret, s->handshake_secret,
                                    &secret_size) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicCreateAppDataServerDecoders(quic) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicCreateHandshakeClientEncoders(quic) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    return QUIC_FLOW_RET_FINISH;
}

QuicFlowReturn TlsClntNewSessionTicketProc(TLS *s, void *packet)
{
    QUIC *quic = QuicTlsTrans(s);
    RPacket *pkt = packet;
    QuicSessionTicket *t = NULL;
    RPacket nonce = {};
    const uint8_t *ticket = NULL;
    uint32_t ticket_lifetime_hint = 0;
    uint32_t age_add = 0;
    uint32_t ticket_len = 0;

    if (RPacketGet4(pkt, &ticket_lifetime_hint) < 0) {
        QUIC_LOG("Get ticket lifetime hint!\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet4(pkt, &age_add) < 0) {
        QUIC_LOG("Get age add!\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGetLengthPrefixed1(pkt, &nonce) < 0) {
        QUIC_LOG("Get nonce failed!\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (RPacketGet2(pkt, &ticket_len) < 0) {
        QUIC_LOG("Get ticket len!\n");
        return QUIC_FLOW_RET_ERROR;
    }
    
    if (ticket_len == 0) {
        return QUIC_FLOW_RET_FINISH;
    }

    if (RPacketGetBytes(pkt, &ticket, ticket_len) < 0) {
        QUIC_LOG("Get ticket failed!\n");
        return QUIC_FLOW_RET_ERROR;
    }

    t = QuicSessionTicketNew(ticket_lifetime_hint, age_add, ticket, ticket_len);
    if (t == NULL) {
        QUIC_LOG("New session ticket failed!\n");
        return QUIC_FLOW_RET_ERROR;
    }

    QuicSessionTicketAdd(quic->session, t);

    if (TlsClntParseExtensions(s, pkt, TLSEXT_NEW_SESSION_TICKET, NULL,
                0) < 0) {
        QUIC_LOG("Parse Extension failed!\n");
        return QUIC_FLOW_RET_ERROR;
    }

    if (QuicSessionMasterKeyGen(s, t, &nonce) < 0) {
        return QUIC_FLOW_RET_ERROR;
    }

    QUIC_LOG("innn\n");
    return QUIC_FLOW_RET_FINISH;
}

static int TlsClntEncExtPostWork(TLS *s)
{
    QUIC *quic = QuicTlsTrans(s);

    if (QuicStreamInit(quic) < 0) {
        return -1;
    }

    return 0;
}

static int TlsClntFinishedPostWork(TLS *s)
{
    return QuicCreateAppDataClientEncoders(QuicTlsTrans(s));
}

int TlsClntSkipCheckCertRequest(TLS *s)
{
    return 0;
}

int TlsClntSkipCheckServerCert(TLS *s)
{
    if (!s->hit) {
        return -1;
    }

    return 0;
}

int TlsClntSkipCheckCertVerify(TLS *s)
{
    if (!s->hit) {
        return -1;
    }

    return 0;
}

