/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"

#include "statem.h"
#include "tls.h"

static QUIC_METHOD QuicClientMeth = {
    .version = QUIC_VERSION_1,
    .quic_handshake = QuicConnect,
    .tls_init = QuicTlsClientInit,
}; 

static QUIC_METHOD QuicServerMeth = {
    .version = QUIC_VERSION_1,
    .quic_handshake = QuicAccept,
    .tls_init = QuicTlsServerInit,
}; 


QUIC_METHOD *QuicClientMethod(void)
{
    return &QuicClientMeth;
}

QUIC_METHOD *QuicServerMethod(void)
{
    return &QuicServerMeth;
}
