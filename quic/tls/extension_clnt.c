/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include <stddef.h>
#include <tbquic/quic.h>
#include "sig_alg.h"
#include "quic_local.h"
#include "common.h"
#include "packet_format.h"
#include "log.h"

static int TlsExtClientConstructServerName(QUIC_TLS *, WPacket *, uint32_t,
                                            X509 *, size_t);
static int TlsExtClientCheckServerName(QUIC_TLS *);

static int TlsExtClientParseSigAlgs(QUIC_TLS *, RPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClientConstructSigAlgs(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                                        size_t);
static int TlsExtClientConstructQuicTransParam(QUIC_TLS *, WPacket *, uint32_t,
                                        X509 *, size_t);

static const QuicTlsExtensionDefinition client_ext_defs[EXT_TYPE_MAX] = {
    [EXT_TYPE_SERVER_NAME] = {
        .context = TLSEXT_CLIENT_HELLO,
        .init = TlsExtInitServerName,
        .check = TlsExtClientCheckServerName,
        .construct = TlsExtClientConstructServerName,
        .final = TlsExtFinalServerName,
    },
    [EXT_TYPE_SIGNATURE_ALGORITHMS] = {
        .context = TLSEXT_CLIENT_HELLO,
        .init = TlsExtInitSigAlgs,
        .parse = TlsExtClientParseSigAlgs,
        .construct = TlsExtClientConstructSigAlgs,
        .final = TlsExtFinalSigAlgs,
    },
    [EXT_TYPE_QUIC_TRANS_PARAMS] = {
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClientConstructQuicTransParam,
    },
};

#define TLS_CLIENT_EXTENSION_DEF_NUM QUIC_ARRAY_SIZE(client_ext_defs)

static int QuicTransParamCheckGrease(QuicTransParams *, size_t);
static int QuicTransParamConstructGrease(QuicTransParams *, size_t, WPacket *);
static int QuicTransParamConstructSourceConnId(QuicTransParams *, size_t,
                                                WPacket *);
static int QuicTransParamCheckGoogleVersion(QuicTransParams *, size_t);
static int QuicTransParamConstructGoogleVersion(QuicTransParams *, size_t,
                                                WPacket *);

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

#define QUIC_TRANS_PARAM_NUM QUIC_ARRAY_SIZE(client_transport_param)

static int TlsExtClientCheckServerName(QUIC_TLS *)
{
    return -1;
}

static int TlsExtClientConstructServerName(QUIC_TLS *tls, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    return 0;
}

static int TlsExtClientParseSigAlgs(QUIC_TLS *tls, RPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx)
{
    return 0;
}

static int TlsExtClientConstructSigAlgs(QUIC_TLS *tls, WPacket *pkt,
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

static int TlsExtClientConstructQuicTransParam(QUIC_TLS *tls, WPacket *pkt,
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

static int QuicTransParamCheckGrease(QuicTransParams *param, size_t offset)
{
#ifdef QUIC_TEST
    return 0;
#endif
    return -1;
}

static int QuicTransParamConstructGrease(QuicTransParams *param, size_t offset,
                                            WPacket *pkt)
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

static int QuicTransParamConstructSourceConnId(QuicTransParams *param,
                                            size_t offset, WPacket *pkt)
{
    QUIC *quic = NULL;
    QUIC_TLS *tls = NULL;

    tls = QUIC_CONTAINER_OF(param, QUIC_TLS, trans_param);
    quic = QuicTlsTrans(tls);

    return QuicTransParamConstructCid(&quic->scid, pkt);
}

static int QuicTransParamCheckGoogleVersion(QuicTransParams *param,
                                            size_t offset)
{
#ifdef QUIC_TEST
    return 0;
#endif
    return -1;
}

static int QuicTransParamConstructGoogleVersion(QuicTransParams *param,
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

