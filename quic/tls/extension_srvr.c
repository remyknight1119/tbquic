/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "extension.h"

int TlsExtParseCtosServerName(QUIC_TLS *, RPacket *, uint32_t, X509 *, size_t)
{
    return 0;
}

int TlsExtParseCtosSigAlgs(QUIC_TLS *quic, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx)
{
    return 0;
}

int TlsExtConstructStocSigAlgs(QUIC_TLS *, WPacket *, uint32_t, X509 *, size_t)
{
    return 0;
}
