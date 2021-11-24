/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"


#include "common.h"

int TlsExtInitServerName(QUIC_TLS *, uint32_t);
int TlsExtFinalServerName(QUIC_TLS *, uint32_t, int);

static const QuicTlsExtensionDefinition ext_defs[] = {
    [EXT_TYPE_SERVER_NAME] = {
        .context = TLS_EXT_CLIENT_HELLO,
        .init = TlsExtInitServerName,
        .parse_ctos = NULL,
        .parse_stoc = TlsExtParseStocServerName,
        .construct_stoc = NULL,
        .construct_ctos = TlsExtConstructCtosServerName,
        .final = TlsExtFinalServerName,
    },
};

#define TLS_EXTENSION_DEF_NUM QUIC_ARRAY_SIZE(ext_defs)

int TlsExtInitServerName(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

int TlsExtFinalServerName(QUIC_TLS *tls, uint32_t context, int sent)
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


int TlsConstructExtensions(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                             X509 *x, size_t chainidx)
{
    const QuicTlsExtensionDefinition *thisexd = NULL;
    ExtensionConstruct construct = NULL;
    size_t i = 0;
    int ret = 0;

    for (i = 0, thisexd = ext_defs; i < TLS_EXTENSION_DEF_NUM; i++, thisexd++) {
        /* Skip if not relevant for our context */
        if (!TlsShouldAddExtension(tls, thisexd->context, context)) {
            continue;
        }

        construct = tls->server ? thisexd->construct_stoc
                              : thisexd->construct_ctos;

        if (construct == NULL) {
            continue;
        }

        ret = construct(tls, pkt, context, x, chainidx);
        if (ret < 0) {
            return -1;
        }
    }

    return 0;
}


