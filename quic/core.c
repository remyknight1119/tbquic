/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"
#include "format.h"
#include "common.h"

static int QuicCryptoOffset[QUIC_PKT_TYPE_MAX] = {
    [QUIC_PKT_TYPE_INITIAL] = offsetof(QUIC, initial),
    [QUIC_PKT_TYPE_0RTT] =  offsetof(QUIC, application),
    [QUIC_PKT_TYPE_HANDSHAKE] = offsetof(QUIC, handshake),
    [QUIC_PKT_TYPE_1RTT] =  offsetof(QUIC, application),
};

QUIC_CRYPTO *QuicCryptoGet(QUIC *quic, uint32_t pkt_type)
{
    int offset = 0;

    if (QUIC_GE(pkt_type, QUIC_PKT_TYPE_MAX)) {
        return NULL;
    }

    offset = QuicCryptoOffset[pkt_type];

    return (void *)((uint8_t *)quic + offset);
}

QUIC_CRYPTO *QuicGetInitialCrypto(QUIC *quic)
{
    return QuicCryptoGet(quic, QUIC_PKT_TYPE_INITIAL);
}

QUIC_CRYPTO *QuicGetHandshakeCrypto(QUIC *quic)
{
    return QuicCryptoGet(quic, QUIC_PKT_TYPE_HANDSHAKE);
}

QUIC_CRYPTO *QuicGetOneRttCrypto(QUIC *quic)
{
    return QuicCryptoGet(quic, QUIC_PKT_TYPE_1RTT);
}


