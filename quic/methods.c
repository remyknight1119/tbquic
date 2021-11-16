/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"

#include "statem.h"
#include "tls.h"

static QUIC_METHOD QuicClientMeth = {
    .quic_handshake = QuicConnect,
    .tls_handshake = QuicTlsConnect,
}; 

static QUIC_METHOD QuicServerMeth = {
    .quic_handshake = QuicAccept,
    .tls_handshake = QuicTlsAccept,
    .server = 1,
}; 



QUIC_METHOD *QuicClientMethod(void)
{
    return &QuicClientMeth;
}

QUIC_METHOD *QuicServerMethod(void)
{
    return &QuicServerMeth;
}
