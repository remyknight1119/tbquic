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
#include "log.h"

static int TlsClientHelloBuild(TLS *, void *);
static int TlsServerHelloProc(TLS *, void *);
static int TlsEncExtProc(TLS *, void *);
static int TlsServerCertProc(TLS *, void *);
static int TlsCertVerifyProc(TLS *, void *);
static int TlsFinishedProc(TLS *, void *);

static const TlsProcess client_proc[HANDSHAKE_MAX] = {
    [TLS_ST_OK] = {
        .flow_state = QUIC_FLOW_NOTHING,
        .next_state = TLS_ST_CW_CLIENT_HELLO,
    },
    [TLS_ST_CW_CLIENT_HELLO] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_CR_SERVER_HELLO,
        .handshake_type = CLIENT_HELLO,
        .handler = TlsClientHelloBuild,
    },
    [TLS_ST_CR_SERVER_HELLO] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_ENCRYPTED_EXTENSIONS,
        .handshake_type = SERVER_HELLO,
        .handler = TlsServerHelloProc,
    },
    [TLS_ST_CR_ENCRYPTED_EXTENSIONS] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_SERVER_CERTIFICATE,
        .handshake_type = ENCRYPTED_EXTENSIONS,
        .handler = TlsEncExtProc,
    },
    [TLS_ST_CR_SERVER_CERTIFICATE] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_CERT_VERIFY,
        .handshake_type = CERTIFICATE,
        .handler = TlsServerCertProc,
    },
    [TLS_ST_CR_CERT_VERIFY] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CR_FINISHED,
        .handshake_type = CERTIFICATE_VERIFY,
        .handler = TlsCertVerifyProc,
    },
    [TLS_ST_CR_FINISHED] = {
        .flow_state = QUIC_FLOW_READING,
        .next_state = TLS_ST_CW_FINISHED,
        .handshake_type = FINISHED,
        .handler = TlsFinishedProc,
    },
    [TLS_ST_CW_FINISHED] = {
        .flow_state = QUIC_FLOW_WRITING,
        .next_state = TLS_ST_HANDSHAKE_DONE,
        .handshake_type = FINISHED,
        .handler = TlsFinishedBuild,
    },
    [TLS_ST_HANDSHAKE_DONE] = {
        .flow_state = QUIC_FLOW_FINISHED,
    },
};

static QuicFlowReturn TlsConnect(TLS *tls)
{
    return TlsHandshake(tls, client_proc, QUIC_NELEM(client_proc));
}

static int TlsClientHelloBuild(TLS *tls, void *packet)
{
    WPacket *pkt = packet;

    if (WPacketPut2(pkt, TLS_VERSION_1_2) < 0) {
        QUIC_LOG("Put leagacy version failed\n");
        return -1;
    }

    if (TlsGenRandom(tls->client_random, sizeof(tls->client_random),
                            pkt) < 0) {
        QUIC_LOG("Generate Client Random failed\n");
        return -1;
    }

    if (WPacketPut1(pkt, 0) < 0) {
        QUIC_LOG("Put session ID len failed\n");
        return -1;
    }

    if (TlsPutCipherList(tls, pkt) < 0) {
        QUIC_LOG("Put cipher list failed\n");
        return -1;
    }

    if (WPacketPut1(pkt, 1) < 0) {
        QUIC_LOG("Put compression len failed\n");
        return -1;
    }

    if (TlsPutCompressionMethod(pkt) < 0) {
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

static int TlsServerHelloProc(TLS *tls, void *packet)
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
        return -1;
    }

    if (TlsParseCipherList(&cipher_list, pkt, 2) < 0) {
        QUIC_LOG("Parse cipher list failed\n");
        return -1;
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
        return -1;
    }

    cipher = TlsCipherMatchListById(&tls->cipher_list, id);
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
        QUIC_LOG("Parse Extension failed\n");
        return -1;
    }

    tls->handshake_msg_len = RPacketTotalLen(pkt);
    //change cipher state
    if (QuicCreateHandshakeServerDecoders(quic) < 0) {
        QUIC_LOG("Create Handshake Decoders failed\n");
        return -1;
    }

    tls->handshake_msg_len = 0;
    QuicBufClear(QUIC_TLS_BUFFER(quic));
    return 0;
}

static int TlsEncExtProc(TLS *tls, void *packet)
{
    QUIC_LOG("in\n");
    return TlsClientParseExtensions(tls, packet, TLSEXT_SERVER_HELLO, NULL, 0);
}

static int TlsServerCertProc(TLS *s, void *packet)
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
    int ret = -1;

    if (RPacketGet1(pkt, &context) < 0) {
        return -1;
    }

    if (RPacketGet3(pkt, &cert_list_len) < 0) {
        return -1;
    }

    if (RPacketRemaining(pkt) != cert_list_len) {
        return -1;
    }

    if ((sk = sk_X509_new_null()) == NULL) {
        return -1;
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
        
        if (RPacketRemaining(&extensions) && TlsClientParseExtensions(s,
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

    if (TlsHandshakeHash(s, s->cert_verify_hash,
                &s->cert_verify_hash_len) < 0) {
        goto out;
    }

    ret = 0;
out:
    QUIC_LOG("in\n");
    X509_free(x);
    sk_X509_pop_free(sk, X509_free);
    return ret;
}

static int TlsCertVerifyProc(TLS *s, void *packet)
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
        return -1;
    }

    if (TlsLookupSigAlgByPkey(pkey) == NULL) {
        return -1;
    }

    if (RPacketGet2(pkt, &sigalg) < 0) {
        return -1;
    }

    if (TlsCheckPeerSigalg(s, sigalg, pkey) < 0) {
        return -1;
    }

    md = TlsLookupMd(s->peer_sigalg);
    if (md == NULL) {
        return -1;
    }

    if (RPacketGet2(pkt, &len) < 0) {
        return -1;
    }

    pkey_size = EVP_PKEY_size(pkey);
    if (pkey_size != len) {
        return -1;
    }

    if (RPacketGetBytes(pkt, &data, len) < 0) {
        return -1;
    }

    if (TlsDoCertVerify(s, data, len, pkey, md) < 0) {
        return -1;
    }

    QUIC_LOG("sigalg = %x, len = %u, pkey size  = %d\n", sigalg, len, pkey_size);
    return 0;
}

static int TlsFinishedProc(TLS *tls, void *packet)
{
    QUIC_LOG("in\n");
    return 0;
}

void TlsClientInit(TLS *tls)
{
    tls->handshake = TlsConnect;
}
