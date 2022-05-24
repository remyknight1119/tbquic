/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_local.h"

#include "statem.h"
#include "tls.h"
#include "datagram.h"
#include "dispenser.h"

static QUIC_METHOD QuicClientMeth = {
    .version = QUIC_VERSION_1,
    .alloc_rbuf = true,
    .quic_connect = QuicConnect,
    .parse_dcid = QuicClntParseDcid,
    .parse_scid = QuicClntParseScid,
    .read_bytes = QuicStatemReadBytes,
    .write_bytes = QuicDatagramSendBytes,
}; 

static QUIC_METHOD QuicServerMeth = {
    .version = QUIC_VERSION_1,
    .alloc_rbuf = true,
    .quic_accept = QuicAccept,
    .parse_dcid = QuicSrvrParseDcid,
    .parse_scid = QuicSrvrParseScid,
    .read_bytes = QuicStatemReadBytes,
    .write_bytes = QuicDatagramSendBytes,
}; 

static QUIC_METHOD QuicDispenserMeth = {
    .version = QUIC_VERSION_1,
    .alloc_rbuf = false,
    .quic_accept = QuicAccept,
    .parse_dcid = QuicSrvrParseDcid,
    .parse_scid = QuicSrvrParseScid,
    .read_bytes = QuicDispenserReadBytes,
    .write_bytes = QuicDispenserWriteBytes,
}; 

QUIC_METHOD *QuicClientMethod(void)
{
    return &QuicClientMeth;
}

QUIC_METHOD *QuicServerMethod(void)
{
    return &QuicServerMeth;
}

QUIC_METHOD *QuicDispenserMethod(void)
{
    return &QuicDispenserMeth;
}

