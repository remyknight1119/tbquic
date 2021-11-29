/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include "common.h"
#include "log.h"

static int TlsExtInitServerName(QUIC_TLS *, uint32_t);
static int TlsExtFinalServerName(QUIC_TLS *, uint32_t, int);
static int TlsExtInitSigAlgs(QUIC_TLS *, uint32_t);
static int TlsExtFinalSigAlgs(QUIC_TLS *, uint32_t, int);

static const QuicTlsExtensionDefinition ext_defs[EXT_TYPE_MAX] = {
    [EXT_TYPE_SERVER_NAME] = {
        .context = TLSEXT_CLIENT_HELLO,
        .init = TlsExtInitServerName,
        .parse_ctos = TlsExtParseCtosServerName,
        .parse_stoc = NULL,
        .construct_stoc = NULL,
        .construct_ctos = TlsExtConstructCtosServerName,
        .final = TlsExtFinalServerName,
    },
    [EXT_TYPE_SIGNATURE_ALGORITHMS] = {
        .context = TLSEXT_CLIENT_HELLO,
        .init = TlsExtInitSigAlgs,
        .parse_ctos = TlsExtParseCtosSigAlgs,
        .parse_stoc = TlsExtParseStocSigAlgs,
        .construct_stoc = TlsExtConstructStocSigAlgs,
        .construct_ctos = TlsExtConstructCtosSigAlgs,
        .final = TlsExtFinalSigAlgs,
    },
};

#define TLS_EXTENSION_DEF_NUM QUIC_ARRAY_SIZE(ext_defs)

static int TlsExtInitServerName(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

static int TlsExtFinalServerName(QUIC_TLS *tls, uint32_t context, int sent)
{
    return 0;
}

static int TlsExtInitSigAlgs(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

static int TlsExtFinalSigAlgs(QUIC_TLS *tls, uint32_t context, int sent)
{
    return 0;
}

static int TlsShouldAddExtension(QUIC_TLS *tls, uint32_t extctx,
                                    uint32_t thisctx)
{
    /* Skip if not relevant for our context */
    if ((extctx & thisctx) == 0) {
        return 0;
    }

    return 1;
}

#ifdef QUIC_TEST
const QuicTlsExtensionDefinition *(*QuicTestExtensionHook)(const
        QuicTlsExtensionDefinition *, size_t *i);
#endif
int TlsConstructExtensions(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx)
{
    const QuicTlsExtensionDefinition *thisexd = NULL;
    ExtensionConstruct construct = NULL;
    size_t i = 0;
    int ret = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    for (i = 0; i < TLS_EXTENSION_DEF_NUM; i++) {
        thisexd = &ext_defs[i];
#ifdef QUIC_TEST
        if (QuicTestExtensionHook) {
            thisexd = QuicTestExtensionHook(ext_defs, &i);
        }
#endif
        /* Skip if not relevant for our context */
        if (!TlsShouldAddExtension(tls, thisexd->context, context)) {
            continue;
        }

        construct = tls->server ? thisexd->construct_stoc
                              : thisexd->construct_ctos;

        if (construct == NULL) {
            continue;
        }

        if (WPacketPut2(pkt, i) < 0) {
            QUIC_LOG("Put session ID len failed\n");
            return -1;
        }

        if (WPacketStartSubU16(pkt) < 0) { 
            return -1;
        }

        ret = construct(tls, pkt, context, x, chainidx);
        if (WPacketClose(pkt) < 0) {
            QUIC_LOG("Close packet failed\n");
            return -1;
        }

        if (ret < 0) {
            return -1;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}


