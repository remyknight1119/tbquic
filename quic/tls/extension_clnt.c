/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

#include "sig_alg.h"
#include "log.h"

int TlsExtConstructCtosServerName(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    return 0;
}

int TlsExtParseStocSigAlgs(QUIC_TLS *tls, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    return 0;
}

int TlsExtConstructCtosSigAlgs(QUIC_TLS *tls, WPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
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
