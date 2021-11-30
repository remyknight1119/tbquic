/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include "packet_format.h"
#include "log.h"

int TlsExtInitServerName(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

int TlsExtFinalServerName(QUIC_TLS *tls, uint32_t context, int sent)
{
    return 0;
}

int TlsExtInitSigAlgs(QUIC_TLS *tls, uint32_t context)
{
    return 0;
}

int TlsExtFinalSigAlgs(QUIC_TLS *tls, uint32_t context, int sent)
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
                             X509 *x, size_t chainidx,
                             const QuicTlsExtensionDefinition *ext,
                             size_t num)
{
    const QuicTlsExtensionDefinition *thisexd = NULL;
    size_t i = 0;
    int ret = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    for (i = 0; i < num; i++) {
        thisexd = &ext[i];
#ifdef QUIC_TEST
        if (QuicTestExtensionHook) {
            thisexd = QuicTestExtensionHook(ext, &i);
        }
#endif
        /* Skip if not relevant for our context */
        if (!TlsShouldAddExtension(tls, thisexd->context, context)) {
            continue;
        }

        if (thisexd->check != NULL && thisexd->check(tls) < 0) {
            continue;
        }

        if (thisexd->construct == NULL) {
            continue;
        }

        if (WPacketPut2(pkt, i) < 0) {
            QUIC_LOG("Put session ID len failed\n");
            return -1;
        }

        if (WPacketStartSubU16(pkt) < 0) { 
            return -1;
        }

        ret = thisexd->construct(tls, pkt, context, x, chainidx);
        if (ret < 0) {
            return -1;
        }
        if (WPacketClose(pkt) < 0) {
            QUIC_LOG("Close packet failed\n");
            return -1;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

int TlsConstructQuicTransportParamExtension(QUIC_TLS *tls, WPacket *pkt,
                                QuicTransportParamDefinition *param,
                                size_t num)
{
    QuicTransportParamDefinition *p = NULL;
    size_t i = 0;

    if (WPacketStartSubU16(pkt) < 0) { 
        return -1;
    }

    for (i = 0; i < num; i++) {
        p = param + i;
        if (p->check && p->check(tls) < 0) {
            continue;
        }

        if (QuicVariableLengthWrite(pkt, p->type) < 0) {
            return -1;
        }

        if (p->construct == NULL) {
            continue;
        }

        if (p->construct(tls, pkt) < 0) {
            return -1;
        }
    }

    if (WPacketClose(pkt) < 0) {
        QUIC_LOG("Close packet failed\n");
        return -1;
    }

    return 0;
}

