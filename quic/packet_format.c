/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_format.h"

#include "common.h"

static int QuicInitPacketHandler(Packet *);
static int Quic0RttPacketHandler(Packet *);
static int QuicHandshakePacketHandler(Packet *);
static int QuicRetryPacketHandler(Packet *);

static QuicLongPacketProcess LPacketProcess[] = {
    {
        .type = QUIC_LPACKET_TYPE_INITIAL,
        .handler = QuicInitPacketHandler,
    },
    {
        .type = QUIC_LPACKET_TYPE_0RTT,
        .handler = Quic0RttPacketHandler,
    },
    {
        .type = QUIC_LPACKET_TYPE_HANDSHAKE,
        .handler = QuicHandshakePacketHandler,
    },
    {
        .type = QUIC_LPACKET_TYPE_RETRY,
        .handler = QuicRetryPacketHandler,
    },
};

#define LPACKET_HANDLER_NUM     QUIC_ARRAY_SIZE(LPacketProcess) 

static QuicPacketHandler QuicLongPacketHandlerFind(uint8_t flags)
{
    uint8_t type = 0;
    int i = 0;

    type = QUIC_PACKET_HEADER_GET_TYPE(flags);
    for (i = 0; i < LPACKET_HANDLER_NUM; i++) {
        if (LPacketProcess[i].type == type) {
            return LPacketProcess[i].handler;
        }
    }

    return NULL;
}

static QuicPacketHandler QuicShortPacketHandlerFind(uint8_t flags)
{
    return NULL;
}

QuicPacketHandler QuicPacketHandlerFind(uint8_t flags)
{
    if (QUIC_PACKET_IS_LONG_PACKET(flags)) {
        return QuicLongPacketHandlerFind(flags);
    }

    return QuicShortPacketHandlerFind(flags);
}

static int QuicInitPacketHandler(Packet *pkt)
{
    printf("IIIint\n");
    return 0;
}

static int Quic0RttPacketHandler(Packet *pkt)
{
    return 0;
}

static int QuicHandshakePacketHandler(Packet *pkt)
{
    return 0;
}

static int QuicRetryPacketHandler(Packet *pkt)
{
    return 0;
}

