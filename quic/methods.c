/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"

#include "statem.h"
#include "tls.h"

static const TlsMethod QuicTlsClientMeth = {
    .handshake = TlsConnect,
}; 

static const TlsMethod QuicTlsServerMeth = {
    .handshake = TlsAccept,
}; 

static QUIC_METHOD QuicClientMeth = {
    .version = QUIC_VERSION_1,
    .quic_connect = QuicConnect,
    .tls_method = &QuicTlsClientMeth,
}; 

static QUIC_METHOD QuicServerMeth = {
    .version = QUIC_VERSION_1,
    .quic_accept = QuicAccept,
    .tls_method = &QuicTlsServerMeth,
}; 

QUIC_METHOD *QuicClientMethod(void)
{
    return &QuicClientMeth;
}

QUIC_METHOD *QuicServerMethod(void)
{
    return &QuicServerMeth;
}
