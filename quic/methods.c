/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"

#include "statem.h"

static QUIC_METHOD QuicClientMeth = {
    .handshake = QuicConnect,
}; 

static QUIC_METHOD QuicServerMeth = {
    .handshake = QuicAccept,
}; 



QUIC_METHOD *QuicClientMethod(void)
{
    return &QuicClientMeth;
}

QUIC_METHOD *QuicServerMethod(void)
{
    return &QuicServerMeth;
}
