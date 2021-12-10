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
#include "log.h"

static int TlsExtClntCheckServerName(QUIC_TLS *);
static int TlsExtClntConstructServerName(QUIC_TLS *, WPacket *, uint32_t,
                                            X509 *, size_t);
static int TlsExtClntConstructSupportedGroups(QUIC_TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtClntParseSigAlgs(QUIC_TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntConstructSigAlgs(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntConstructQuicTransParam(QUIC_TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtClntCheckAlpn(QUIC_TLS *);
static int TlsExtClntConstructAlpn(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClntConstructSupportedVersion(QUIC_TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtClntConstructKeyExchModes(QUIC_TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtClntConstructKeyShare(QUIC_TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);
static int TlsExtClntCheckUnknown(QUIC_TLS *);
static int TlsExtClntConstructUnknown(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);

static const QuicTlsExtensionDefinition client_ext_defs[] = {
    {
        .type = EXT_TYPE_SERVER_NAME,
        .context = TLSEXT_CLIENT_HELLO,
        .init = TlsExtInitServerName,
        .check = TlsExtClntCheckServerName,
        .construct = TlsExtClntConstructServerName,
        .final = TlsExtFinalServerName,
    },
    {
        .type = EXT_TYPE_SUPPORTED_GROUPS,
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClntConstructSupportedGroups,
    },
    {
        .type = EXT_TYPE_SIGNATURE_ALGORITHMS,
        .context = TLSEXT_CLIENT_HELLO,
        .init = TlsExtInitSigAlgs,
        .parse = TlsExtClntParseSigAlgs,
        .construct = TlsExtClntConstructSigAlgs,
        .final = TlsExtFinalSigAlgs,
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
        .construct = TlsExtClntConstructQuicTransParam,
    },
    {
        .type = 0x4469,
        .context = TLSEXT_CLIENT_HELLO,
        .check = TlsExtClntCheckUnknown,
        .construct = TlsExtClntConstructUnknown,
    },
};

#define TLS_CLIENT_EXTENSION_DEF_NUM QUIC_NELEM(client_ext_defs)

static int QuicTransParamCheckGrease(QUIC_TLS *, QuicTransParams *, size_t);
static int QuicTransParamConstructGrease(QUIC_TLS *, QuicTransParams *,
                                            size_t, WPacket *);
static int QuicTransParamConstructSourceConnId(QUIC_TLS *, QuicTransParams *,
                                            size_t, WPacket *);
static int QuicTransParamCheckGoogleVersion(QUIC_TLS *, QuicTransParams *,
                                            size_t);
static int QuicTransParamConstructGoogleVersion(QUIC_TLS *, QuicTransParams *,
                                            size_t, WPacket *);

static QuicTransParamDefinition client_transport_param[] = {
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID,
//        .parse = ,
        .construct = QuicTransParamConstructSourceConnId,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
//        .parse = ,
        .check = QuicTransParamCheckInteger,
        .construct = QuicTransParamConstructInteger,
    },
    {
        //GREASE
        .type = 0x1CD4C8D5641422F0,
        .check = QuicTransParamCheckGrease,
        .construct = QuicTransParamConstructGrease,
    },
    {
        //Google QUIC Version
        .type = 0x4752,
        .check = QuicTransParamCheckGoogleVersion,
        .construct = QuicTransParamConstructGoogleVersion,
    },
};

#define QUIC_TRANS_PARAM_NUM QUIC_NELEM(client_transport_param)

static int TlsExtClntCheckServerName(QUIC_TLS *tls)
{
    if (tls->ext.hostname == NULL) {
        return -1;
    }

    return 0;
}

static int TlsExtClntConstructServerName(QUIC_TLS *tls, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    const char *hostname = tls->ext.hostname;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    if (WPacketPut1(pkt, TLSEXT_NAMETYPE_HOST_NAME) < 0) {
        return -1;
    }

    if (WPacketSubMemcpyU16(pkt, hostname, strlen(hostname)) < 0) {
        return -1;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

static int TlsExtClntConstructSupportedGroups(QUIC_TLS *tls, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    const uint16_t *pgroups = NULL;
    uint16_t id = 0;
    size_t pgroupslen = 0;
    size_t i = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    TlsGetSupportedGroups(tls, &pgroups, &pgroupslen);

    for (i = 0; i < pgroupslen; i++) {
        id = pgroups[i];
        if (WPacketPut2(pkt, id) < 0) {
            return -1;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

static int TlsExtClntParseSigAlgs(QUIC_TLS *tls, RPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    return 0;
}

static int TlsExtClntConstructSigAlgs(QUIC_TLS *tls, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    const uint16_t *salg = NULL;
    size_t salglen = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    salglen = TlsGetPSigAlgs(tls, &salg);
    if (TlsCopySigAlgs(pkt, salg, salglen) < 0) {
        return -1;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

static int TlsExtClntCheckAlpn(QUIC_TLS *tls)
{
    if (QuicDataIsEmpty(&tls->ext.alpn)) {
        return -1;
    }

    return 0;
}

static int TlsExtClntConstructAlpn(QUIC_TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    QUIC_DATA *alpn = &tls->ext.alpn;

    return WPacketSubMemcpyU16(pkt, alpn->data, alpn->len);
}

static int TlsExtClntConstructSupportedVersion(QUIC_TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    if (WPacketStartSubU8(pkt) < 0) { 
        return -1;
    }

    if (WPacketPut2(pkt, TLS_VERSION_1_3) < 0) {
        return -1;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

static int TlsExtClntConstructKeyExchModes(QUIC_TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    if (WPacketStartSubU8(pkt) < 0) {
        return -1;
    }

    if (WPacketPut1(pkt, TLSEXT_KEX_MODE_KE_DHE) < 0) {
        return -1;
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

#ifdef QUIC_TEST
size_t (*QuicTestEncodedpointHook)(unsigned char **point);
#endif
static int TlsExtClntAddKeyShare(QUIC_TLS *tls, WPacket *pkt, uint16_t id)
{
    EVP_PKEY *key_share_key = NULL;
    unsigned char *encoded_point = NULL;
    size_t encodedlen = 0;

    if (tls->tmp_key == NULL) {
        key_share_key = TlsGeneratePkeyGroup(tls, id);
        if (key_share_key == NULL) {
            return -1;
        }
    } else {
        key_share_key = tls->tmp_key;
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

    tls->tmp_key = key_share_key;
    tls->group_id = id;
    OPENSSL_free(encoded_point);
    return 0;
out:
    if (tls->tmp_key == NULL) {
        EVP_PKEY_free(key_share_key);
    }

    OPENSSL_free(encoded_point);
    return -1;
}

static int TlsExtClntConstructKeyShare(QUIC_TLS *tls, WPacket *pkt,
                                        uint32_t context, X509 *x,
                                        size_t chainidx)
{
    const uint16_t *pgroups = NULL;
    size_t pgroupslen = 0;
    size_t max_idx = 0;
    size_t i = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    TlsGetSupportedGroups(tls, &pgroups, &pgroupslen);
    max_idx = tls->ext.key_share_max_group_idx;
    assert(pgroupslen != 0);
    if (max_idx >= pgroupslen) {
        max_idx = pgroupslen - 1;
    }

    for (i = 0; i <= max_idx; i++) {
        if (TlsExtClntAddKeyShare(tls, pkt, pgroups[i]) < 0) {
            return -1;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

static int TlsExtClntCheckUnknown(QUIC_TLS *tls)
{
#ifdef QUIC_TEST
    if (QuicTestExtensionHook) {
        return 0;
    }
#endif
    return -1;
}

static int TlsExtClntConstructUnknown(QUIC_TLS *tls, WPacket *pkt,
                            uint32_t context, X509 *x, size_t chainidx)
{
    uint8_t data[] = "\x00\x03\x02\x68\x33";
    
    return WPacketMemcpy(pkt, data, sizeof(data) - 1);
}

static int TlsExtClntConstructQuicTransParam(QUIC_TLS *tls, WPacket *pkt,
                            uint32_t context, X509 *x, size_t chainidx)
{
    return TlsConstructQuicTransParamExtension(tls, pkt, client_transport_param,
                                    QUIC_TRANS_PARAM_NUM);
}

int TlsClientConstructExtensions(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx)
{
    return TlsConstructExtensions(tls, pkt, context, x, chainidx,
                                    client_ext_defs,
                                    TLS_CLIENT_EXTENSION_DEF_NUM);
}

static int
QuicTransParamCheckGrease(QUIC_TLS *tls, QuicTransParams *param, size_t offset)
{
#ifdef QUIC_TEST
    if (QuicTestTransParamHook) {
        return 0;
    }
#endif
    return -1;
}

static int
QuicTransParamConstructGrease(QUIC_TLS *tls, QuicTransParams *param,
                                size_t offset, WPacket *pkt)
{
    uint8_t value[] = "\xB9\xF8\xCB\xDE\x38\x55\x6D\x9D\x34\x30\x0F\x89";
    size_t len = sizeof(value) - 1;

    if (QuicVariableLengthWrite(pkt, len) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, value, len);
}

int QuicTransParamConstructCid(QUIC_DATA *cid, WPacket *pkt)
{
    if (QuicVariableLengthWrite(pkt, cid->len) < 0) {
        return -1;
    }

    if (cid->len == 0) {
        return 0;
    }

    return WPacketMemcpy(pkt, cid->data, cid->len);
}

static int
QuicTransParamConstructSourceConnId(QUIC_TLS *tls, QuicTransParams *param,
                                            size_t offset, WPacket *pkt)
{
    QUIC *quic = NULL;

    quic = QuicTlsTrans(tls);

    return QuicTransParamConstructCid(&quic->scid, pkt);
}

static int
QuicTransParamCheckGoogleVersion(QUIC_TLS *tls, QuicTransParams *param,
                                    size_t offset)
{
#ifdef QUIC_TEST
    return 0;
#endif
    return -1;
}

static int
QuicTransParamConstructGoogleVersion(QUIC_TLS *tls, QuicTransParams *param,
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

