/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include <stddef.h>
#include <assert.h>
#include <string.h>
#include <tbquic/tls.h>

#include "sig_alg.h"
#include "quic_local.h"
#include "tls_lib.h"
#include "common.h"
#include "format.h"
#include "transport.h"
#include "session.h"
#include "log.h"

static int TlsExtClntCheckServerName(TLS *);
static int TlsExtClntCheckAlpn(TLS *);
static int TlsExtClntCheckPreSharedKey(TLS *);
static int TlsExtClntCheckUnknown(TLS *);
static ExtReturn TlsExtClntConstructServerName(TLS *, WPacket *, uint32_t,
                                            X509 *, size_t);
static ExtReturn TlsExtClntConstructTlsExtQtp(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtClntConstructSupportedGroups(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtClntConstructSupportedVersion(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtClntConstructKeyExchModes(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtClntConstructKeyShare(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtClntConstructAlpn(TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static ExtReturn TlsExtClntConstructPreSharedKey(TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static ExtReturn TlsExtClntConstructUnknown(TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntParseServerName(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntParseAlpn(TLS *, RPacket *, uint32_t, X509 *, size_t);
static int TlsExtClntParsePreSharedKey(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntParseSupportedVersion(TLS *, RPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtClntParseKeyShare(TLS *, RPacket *, uint32_t, X509 *, size_t);
static int TlsExtClntParseTlsExtQtp(TLS *, RPacket *, uint32_t, X509 *, size_t);
static int TlsExtClntParseCertAuthoritites(TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntParseEarlyData(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx);
static int TlsExtClntParsePsk(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                size_t chainidx);

static const TlsExtConstruct kClientExtConstruct[] = {
    {
        .type = EXT_TYPE_SERVER_NAME,
        .context = TLSEXT_CLIENT_HELLO,
        .check = TlsExtClntCheckServerName,
        .construct = TlsExtClntConstructServerName,
    },
    {
        .type = EXT_TYPE_SUPPORTED_GROUPS,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClntConstructSupportedGroups,
    },
    {
        .type = EXT_TYPE_SIGNATURE_ALGORITHMS,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtConstructSigAlgs,
    },
    {
        .type = EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        .context = TLSEXT_CLIENT_HELLO,
        .check = TlsExtClntCheckAlpn,
        .construct = TlsExtClntConstructAlpn,
    },
    {
        .type = EXT_TYPE_SUPPORTED_VERSIONS,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClntConstructSupportedVersion,
    },
    {
        .type = EXT_TYPE_PSK_KEY_EXCHANGE_MODES,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClntConstructKeyExchModes,
    },
    {
        .type = EXT_TYPE_KEY_SHARE,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClntConstructKeyShare,
    },
    {
        .type = EXT_TYPE_QUIC_TRANS_PARAMS,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClntConstructTlsExtQtp,
    },
    {
        .type = 0x4469,
        .context = TLSEXT_CLIENT_HELLO,
        .check = TlsExtClntCheckUnknown,
        .construct = TlsExtClntConstructUnknown,
    },
    {
        .type = EXT_TYPE_PRE_SHARED_KEY,
        .context = TLSEXT_CLIENT_HELLO,
        .check = TlsExtClntCheckPreSharedKey,
        .construct = TlsExtClntConstructPreSharedKey,
    },
};

static const TlsExtParse kClientExtParse[] = {
    {
        .type = EXT_TYPE_SERVER_NAME,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParseServerName,
    },
    {
        .type = EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParseAlpn,
    },
    {
        .type = EXT_TYPE_PRE_SHARED_KEY,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParsePreSharedKey,
    },
    {
        .type = EXT_TYPE_SUPPORTED_VERSIONS,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParseSupportedVersion,
    },
    {
        .type = EXT_TYPE_KEY_SHARE,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParseKeyShare,
    },
    {
        .type = EXT_TYPE_QUIC_TRANS_PARAMS,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParseTlsExtQtp,
    },
    {
        .type = EXT_TYPE_SIGNATURE_ALGORITHMS,
        .context = TLSEXT_CERTIFICATE_REQUEST,
        .parse = TlsExtParseSigAlgs,
    },
    {
        .type = EXT_TYPE_CERTIFICATE_AUTHORITIES,
        .context = TLSEXT_CERTIFICATE_REQUEST,
        .parse = TlsExtClntParseCertAuthoritites,
    },
    {
        .type = EXT_TYPE_EARLY_DATA, 
        .context = TLSEXT_NEW_SESSION_TICKET,
        .parse = TlsExtClntParseEarlyData,
    },
    {
        .type = EXT_TYPE_PRE_SHARED_KEY,
        .context = TLSEXT_SERVER_HELLO,
        .parse = TlsExtClntParsePsk,
    },
};
 
static int TlsExtQtpCheckGrease(TLS *, QuicTransParams *, size_t);
static int TlsExtClntQtpCheckStatelessResetToken(TLS *,
                                QuicTransParams *, size_t);
static int TlsExtQtpConstructGrease(TLS *, QuicTransParams *,
                                            size_t, WPacket *);
static int TlsExtQtpCheckGoogleVersion(TLS *, QuicTransParams *,
                                            size_t);
static int TlsExtQtpConstructGoogleVersion(TLS *, QuicTransParams *,
                                            size_t, WPacket *);
static int TlsExtQtpParseStatelessResetToken(TLS *tls,
                                QuicTransParams *param, size_t offset,
                                RPacket *pkt, uint64_t len);

static TlsExtQtpDefinition kClientTransportParam[] = {
    {
        .type = QUIC_TRANS_PARAM_STATELESS_RESET_TOKEN,
        .parse = TlsExtQtpParseStatelessResetToken,
        .check = TlsExtClntQtpCheckStatelessResetToken,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID,
//        .parse = ,
        .construct = TlsExtQtpConstructSourceConnId,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
        .parse = TlsExtQtpParseInteger,
        .check = TlsExtQtpCheckInteger,
        .construct = TlsExtQtpConstructInteger,
    },
    {
        //GREASE
        .type = 0x1CD4C8D5641422F0,
        .check = TlsExtQtpCheckGrease,
        .construct = TlsExtQtpConstructGrease,
    },
    {
        //Google QUIC Version
        .type = 0x4752,
        .check = TlsExtQtpCheckGoogleVersion,
        .construct = TlsExtQtpConstructGoogleVersion,
    },
};

#define QUIC_TRANS_PARAM_NUM QUIC_NELEM(kClientTransportParam)

static int TlsExtClntQtpCheckStatelessResetToken(TLS *,
                                QuicTransParams *, size_t)
{
    return -1;
}

static int TlsExtClntCheckServerName(TLS *tls)
{
    if (tls->ext.hostname == NULL) {
        return -1;
    }

    return 0;
}

static ExtReturn TlsExtClntConstructServerName(TLS *tls, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    const char *hostname = tls->ext.hostname;

    if (WPacketStartSubU16(pkt) < 0) { 
        return EXT_RETURN_FAIL;
    }

    if (WPacketPut1(pkt, TLSEXT_NAMETYPE_HOST_NAME) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketSubMemcpyU16(pkt, hostname, strlen(hostname)) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static ExtReturn TlsExtClntConstructSupportedGroups(TLS *tls, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    const uint16_t *pgroups = NULL;
    uint16_t id = 0;
    size_t pgroupslen = 0;
    size_t i = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return EXT_RETURN_FAIL;
    }

    TlsGetSupportedGroups(tls, &pgroups, &pgroupslen);

    for (i = 0; i < pgroupslen; i++) {
        id = pgroups[i];
        if (WPacketPut2(pkt, id) < 0) {
            return EXT_RETURN_FAIL;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static int TlsExtClntCheckAlpn(TLS *tls)
{
    if (QuicDataIsEmpty(&tls->ext.alpn)) {
        return -1;
    }

    return 0;
}

static ExtReturn TlsExtClntConstructAlpn(TLS *s, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    QUIC_DATA *alpn = &s->ext.alpn;

    s->alpn_sent = 0;
    if (TlsExtConstructAlpn(alpn, pkt) < 0) {
        return EXT_RETURN_FAIL;
    }
    s->alpn_sent = 1;

    return EXT_RETURN_SENT;
}

static int TlsExtClntCheckPreSharedKey(TLS *s)
{
    QUIC_SESSION *sess = TlsGetSession(s);

    if (sess == NULL || list_empty(&sess->ticket_queue)) {
        return -1;
    }

    return 0;
}

static ExtReturn TlsExtClntConstructPreSharedKey(TLS *s, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    QUIC_SESSION *sess = TlsGetSession(s);
    QuicSessionTicket *t = NULL;
    const EVP_MD *md = NULL;
    uint8_t *binder = NULL;
    uint8_t *msgstart = NULL;
    size_t hashsize = 0;
    size_t binder_offset = 0;
    uint32_t age_ms = 0;

    if (sess->cipher == NULL) {
        return EXT_RETURN_FAIL;
    }

    t = QuicSessionTicketGet(sess, &age_ms);
    if (t == NULL) {
        return EXT_RETURN_NOT_SENT;
    }

    md = QuicMd(sess->cipher->digest);
    if (md == NULL) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketStartSubU16(pkt) < 0) { 
        return EXT_RETURN_FAIL;
    }

    if (WPacketSubMemcpyU16(pkt, t->ticket.data, t->ticket.len) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketPut4(pkt, age_ms) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    binder_offset = WPacket_get_written(pkt);
    if (WPacketStartSubU16(pkt) < 0) { 
        return EXT_RETURN_FAIL;
    }

    hashsize = EVP_MD_size(md);
    if (WPacketSubAllocBytesU8(pkt, hashsize, &binder) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    if (WPacketForceClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    msgstart = WPacket_get_curr(pkt) - WPacket_get_written(pkt);
    
    if (TlsPskDoBinder(s, md, msgstart, binder_offset, NULL, binder, t) < 0) {
        return EXT_RETURN_FAIL;
    }

    QUIC_LOG("Sent\n");
    return EXT_RETURN_SENT;
}

static ExtReturn TlsExtClntConstructSupportedVersion(TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    if (WPacketStartSubU8(pkt) < 0) { 
        return EXT_RETURN_FAIL;
    }

    if (WPacketPut2(pkt, TLS_VERSION_1_3) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static ExtReturn TlsExtClntConstructKeyExchModes(TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    if (WPacketStartSubU8(pkt) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketPut1(pkt, TLSEXT_KEX_MODE_KE_DHE) < 0) {
        return EXT_RETURN_FAIL;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

#ifdef QUIC_TEST
size_t (*QuicTestEncodedpointHook)(unsigned char **point);
#endif
static int TlsExtClntAddKeyShare(TLS *tls, WPacket *pkt, uint16_t id)
{
    EVP_PKEY *key_share_key = NULL;
    unsigned char *encoded_point = NULL;
    size_t encodedlen = 0;

    if (tls->kexch_key == NULL) {
        key_share_key = TlsGeneratePkeyGroup(tls, id);
        if (key_share_key == NULL) {
            return -1;
        }
    } else {
        key_share_key = tls->kexch_key;
    }

    /* Encode the public key. */
    encodedlen = EVP_PKEY_get1_tls_encodedpoint(key_share_key, &encoded_point);
#ifdef QUIC_TEST
    if (QuicTestEncodedpointHook != NULL) {
        encodedlen = QuicTestEncodedpointHook(&encoded_point);
    }
#endif
    if (encodedlen == 0) {
        goto out;
    }

    if (WPacketPut2(pkt, id) < 0) {
        goto out;
    }

    if (WPacketSubMemcpyU16(pkt, encoded_point, encodedlen) < 0) {
        goto out;
    }

    tls->kexch_key = key_share_key;
    tls->group_id = id;

    OPENSSL_free(encoded_point);
    return 0;
out:
    if (tls->kexch_key == NULL) {
        EVP_PKEY_free(key_share_key);
    }

    OPENSSL_free(encoded_point);
    return -1;
}

static ExtReturn TlsExtClntConstructKeyShare(TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    const uint16_t *pgroups = NULL;
    size_t pgroupslen = 0;
    size_t max_idx = 0;
    size_t i = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return EXT_RETURN_FAIL;
    }

    TlsGetSupportedGroups(tls, &pgroups, &pgroupslen);
    max_idx = tls->ext.key_share_max_group_idx;
    assert(pgroupslen != 0);
    if (max_idx >= pgroupslen) {
        max_idx = pgroupslen - 1;
    }

    for (i = 0; i <= max_idx; i++) {
        if (TlsExtClntAddKeyShare(tls, pkt, pgroups[i]) < 0) {
            return EXT_RETURN_FAIL;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static int TlsExtClntCheckUnknown(TLS *tls)
{
#ifdef QUIC_TEST
    if (QuicTestExtensionHook) {
        return 0;
    }
#endif
    return -1;
}

static ExtReturn TlsExtClntConstructUnknown(TLS *tls, WPacket *pkt,
                            uint32_t context, X509 *x, size_t chainidx)
{
    uint8_t data[] = "\x00\x03\x02\x68\x33";
    
    if (WPacketMemcpy(pkt, data, sizeof(data) - 1) < 0) {
        return EXT_RETURN_FAIL;
    }

    return EXT_RETURN_SENT;
}

static ExtReturn TlsExtClntConstructTlsExtQtp(TLS *tls, WPacket *pkt,
                            uint32_t context, X509 *x, size_t chainidx)
{
    return TlsConstructQtpExtension(tls, pkt, kClientTransportParam,
                                    QUIC_TRANS_PARAM_NUM);
}

int TlsClntConstructExtensions(TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx)
{
    return TlsConstructExtensions(tls, pkt, context, x, chainidx,
                                    kClientExtConstruct,
                                    QUIC_NELEM(kClientExtConstruct));
}

static int TlsExtClntParseServerName(TLS *tls, RPacket *pkt,
                                uint32_t context, X509 *x,
                                size_t chainidx)
{
    QUIC_LOG("in\n");
    return 0;
}

static int TlsExtClntParseAlpn(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                size_t chainidx)
{
    uint32_t len = 0;

    if (!s->alpn_sent) {
        return -1;
    }

    if (RPacketGet2(pkt, &len) < 0) {
        return -1;
    }

    if (RPacketRemaining(pkt) != len) {
        return -1;
    }

    if (RPacketGet1(pkt, &len) < 0) {
        return -1;
    }

    if (RPacketRemaining(pkt) != len) {
        return -1;
    }

    if (PRacketMemDup(pkt, &s->alpn_selected.ptr_u8,
                &s->alpn_selected.len) < 0) {
        return -1;
    }

    if (RPacketPull(pkt, RPacketRemaining(pkt)) < 0) {
        return -1;
    }

    return 0;
}

static int TlsExtClntParsePreSharedKey(TLS *s, RPacket *pkt, uint32_t context,
                                            X509 *x, size_t chainidx)
{
    QUIC_SESSION *sess = TlsGetSession(s);
    uint32_t identity = 0;

    if (RPacketGet2(pkt, &identity) < 0) {
        return -1;
    }

    if (QUIC_GE(identity, sess->tick_identity)) {
        return -1;
    }

    s->hit = 1;

    return 0;
}
 
static int TlsExtClntParseSupportedVersion(TLS *s, RPacket *pkt,
                            uint32_t context, X509 *x,
                            size_t chainidx)
{
    uint32_t version = 0;

    if (RPacketRemaining(pkt) != 2) {
        return -1;
    }

    if (RPacketGet2(pkt, &version) < 0) {
        return -1;
    }

    if (version != TLS_VERSION_1_3) {
        return -1;
    }

    return 0;
}

static int TlsExtClntParseTlsExtQtp(TLS *s, RPacket *pkt, 
                                uint32_t context, X509 *x,
                                size_t chainidx)
{
    return TlsParseQtpExtension(s, pkt, kClientTransportParam,
                                    QUIC_TRANS_PARAM_NUM);
}

static int TlsCaDnCmp(const X509_NAME *const *a, const X509_NAME *const *b)
{
    return X509_NAME_cmp(*a, *b);
}

static int TlsParseCaNames(TLS *s, RPacket *pkt)
{
    STACK_OF(X509_NAME) *ca_sk = sk_X509_NAME_new(TlsCaDnCmp);
    X509_NAME *xn = NULL;
    QUIC *quic = QuicTlsTrans(s);
    const uint8_t *namebytes = NULL;
    RPacket cadns = {};
    uint32_t name_len = 0;

    if (ca_sk == NULL) {
        QUIC_LOG("CA SK new failed\n");
        goto err;
    }

    /* get the CA RDNs */
    if (RPacketGetLengthPrefixed2(pkt, &cadns) < 0) {
        QUIC_LOG("Get CADNS failed\n");
        goto err;
    }

    while (RPacketRemaining(&cadns)) {
        const unsigned char *namestart = NULL;

        if (RPacketGet2(&cadns, &name_len) < 0) {
            QUIC_LOG("Get CADNS len failed\n");
            goto err;
        }

        if (RPacketGetBytes(&cadns, &namebytes, name_len) < 0) {
            QUIC_LOG("Get CADNS bytes failed\n");
            goto err;
        }

        namestart = (const unsigned char *)namebytes;
        if ((xn = d2i_X509_NAME(NULL, &namebytes, name_len)) == NULL) {
            QUIC_LOG("d2i X509_NAME failed\n");
            goto err;
        }
        if (namebytes != (namestart + name_len)) {
            QUIC_LOG("Name bytesp(%p) and name start(%p) not match\n",
                    namebytes, namestart + name_len);
            goto err;
        }

        if (!sk_X509_NAME_push(ca_sk, xn)) {
            QUIC_LOG("Push xn failed\n");
            goto err;
        }
        xn = NULL;
    }

    sk_X509_NAME_pop_free(quic->peer_ca_names, X509_NAME_free);
    quic->peer_ca_names = ca_sk;

    return 0;

err:
    sk_X509_NAME_pop_free(ca_sk, X509_NAME_free);
    X509_NAME_free(xn);
    return -1;
}

static int
TlsExtClntParseCertAuthoritites(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                    size_t chainidx)
{
    if (TlsParseCaNames(s, pkt) < 0) {
        return -1;
    }

    if (RPacketRemaining(pkt) != 0) {
        return -1;
    }

    return 0;
}

static int TlsExtClntParsePsk(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                size_t chainidx)
{
    QUIC *quic = QuicTlsTrans(s);
    uint32_t identity = 0;

    if (RPacketGet2(pkt, &identity) < 0) {
        return -1;
    }

    if (quic->session == NULL) {
        return -1;
    }

    if (identity >= quic->session->tick_identity) {
        return -1;
    }

    return 0;
}

static int TlsExtClntParseEarlyData(TLS *s, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    QUIC *quic = QuicTlsTrans(s);
    uint32_t max_early_data = 0;

    if (context == TLSEXT_NEW_SESSION_TICKET) {
        if (RPacketGet4(pkt, &max_early_data) < 0) {
            return -1;
        }

        quic->session->max_early_data = max_early_data;
        return 0;
    }

    return 0;
}

static int TlsExtClntParseKeyShare(TLS *tls, RPacket *pkt,
                                uint32_t context, X509 *x,
                                size_t chainidx)
{
    EVP_PKEY *ckey = tls->kexch_key;
    EVP_PKEY *skey = NULL;
    const uint16_t *pgroups = NULL;
    const uint8_t *key_ex_data = NULL;
    size_t pgroupslen = 0;
    size_t max_idx = 0;
    size_t i = 0;
    uint32_t group_id = 0;
    uint32_t key_ex_len = 0;

    if (ckey == NULL) {
        QUIC_LOG("Ckey is NULL\n");
        return -1;
    }

    if (RPacketGet2(pkt, &group_id) < 0) {
        return -1;
    }

    TlsGetSupportedGroups(tls, &pgroups, &pgroupslen);
    max_idx = tls->ext.key_share_max_group_idx;
    assert(pgroupslen != 0);
    if (max_idx >= pgroupslen) {
        max_idx = pgroupslen - 1;
    }

    for (i = 0; i <= max_idx; i++) {
        if (pgroups[i] == group_id) {
            break;
        }
    }

    if (i > max_idx) {
        QUIC_LOG("Group ID %u not found\n",  group_id);
        return -1;
    }

    if (group_id != tls->group_id) {
        QUIC_LOG("Group ID %u not same[%d]\n",  group_id, tls->group_id);
        return -1;
    }

    if (RPacketGet2(pkt, &key_ex_len) < 0) {
        return -1;
    }

    key_ex_data = RPacketData(pkt);
    if (RPacketPull(pkt, key_ex_len) < 0) {
        QUIC_LOG("Pull failed\n");
        return -1;
    }

    skey = EVP_PKEY_new();
    if (skey == NULL || EVP_PKEY_copy_parameters(skey, ckey) <= 0) {
        QUIC_LOG("Copy parameters failed\n");
        EVP_PKEY_free(skey);
        return -1;
    }

    if (!EVP_PKEY_set1_tls_encodedpoint(skey, key_ex_data, key_ex_len)) {
        QUIC_LOG("Set TLS encodedpoint failed\n");
        EVP_PKEY_free(skey);
        return -1;
    }

    if (TlsKeyDerive(tls, ckey, skey) < 0) {
        QUIC_LOG("Derive key failed\n");
        EVP_PKEY_free(skey);
        return -1;
    }

    tls->peer_kexch_key = skey;
    return 0;
}

int TlsClntParseExtensions(TLS *s, RPacket *pkt, uint32_t context, X509 *x,
                                    size_t chainidx)
{
    return TlsParseExtensions(s, pkt, context, x, chainidx, kClientExtParse,
                                    QUIC_NELEM(kClientExtParse));
}

static int
TlsExtQtpCheckGrease(TLS *tls, QuicTransParams *param, size_t offset)
{
#ifdef QUIC_TEST
    if (QuicTestTransParamHook) {
        return 0;
    }
#endif
    return -1;
}

static int
TlsExtQtpConstructGrease(TLS *tls, QuicTransParams *param,
                                size_t offset, WPacket *pkt)
{
    uint8_t value[] = "\xB9\xF8\xCB\xDE\x38\x55\x6D\x9D\x34\x30\x0F\x89";
    size_t len = sizeof(value) - 1;

    if (QuicVariableLengthWrite(pkt, len) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, value, len);
}

static int
TlsExtQtpCheckGoogleVersion(TLS *tls, QuicTransParams *param,
                                    size_t offset)
{
#ifdef QUIC_TEST
    return 0;
#endif
    return -1;
}

static int
TlsExtQtpConstructGoogleVersion(TLS *tls, QuicTransParams *param,
                                            size_t offset, WPacket *pkt)
{
    if (QuicVariableLengthWrite(pkt, 4) < 0) {
        return -1;
    }

    /* Version */
    if (WPacketPut4(pkt, 1) < 0) {
        return -1;
    }

    return 0;
}


static int TlsExtQtpParseStatelessResetToken(TLS *tls,
                                QuicTransParams *param, size_t offset,
                                RPacket *pkt, uint64_t len)
{
    if (len != QUIC_TRANS_PARAM_STATELESS_RESET_TOKEN_LEN) {
        return -1;
    }

    return RPacketCopyBytes(pkt, param->stateless_reset_token, len);
}

