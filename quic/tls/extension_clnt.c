/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include "sig_alg.h"
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
static int TlsExtClientConstructQuicTransportParam(QUIC_TLS *, WPacket *,
                                        uint32_t, X509 *, size_t);

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
    [EXT_TYPE_QUIC_TRANSPORT_PARAMETERS] = {
        .context = TLSEXT_CLIENT_HELLO,
        .construct = TlsExtClientConstructQuicTransportParam,
    },
};

#define TLS_CLIENT_EXTENSION_DEF_NUM QUIC_ARRAY_SIZE(client_ext_defs)


static int QuicTransportParamConstructMaxIdelTimeout(QUIC_TLS *, WPacket *);
static int QuicTransportParamCheckMaxIdelTimeout(QUIC_TLS *);

static QuicTransportParamDefinition client_transport_param[] = {
    {
        .type = QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT,
//        .parse = ,
        .check = QuicTransportParamCheckMaxIdelTimeout,
        .construct = QuicTransportParamConstructMaxIdelTimeout,
    },
};

#define QUIC_TRANSPORT_PARAM_NUM QUIC_ARRAY_SIZE(client_transport_param)

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

static int QuicTransportParamCheckMaxIdelTimeout(QUIC_TLS *tls)
{
    if (tls->trans_param.max_idle_timeout == 0) {
        return -1;
    }

    return 0;
}

static int QuicTransportParamConstructMaxIdelTimeout(QUIC_TLS *tls,
                                                    WPacket *pkt)
{
    return QuicVariableLengthWrite(pkt, tls->trans_param.max_idle_timeout);
}

static int TlsExtClientConstructQuicTransportParam(QUIC_TLS *tls, WPacket *pkt,
                            uint32_t context, X509 *x, size_t chainidx)
{
    return TlsConstructQuicTransportParamExtension(tls, pkt,
                                    client_transport_param,
                                    QUIC_TRANSPORT_PARAM_NUM);
}

int TlsClientConstructExtensions(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx)
{
    return TlsConstructExtensions(tls, pkt, context, x, chainidx,
                                    client_ext_defs,
                                    TLS_CLIENT_EXTENSION_DEF_NUM);
}


