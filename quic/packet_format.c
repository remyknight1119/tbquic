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

static int QuicVariableLengthValueEncode(uint8_t *buf, size_t blen,
        uint64_t length, uint8_t prefix)
{
    QuicVarLenFirstByte *var = NULL;
    uint8_t len = 0;
    uint8_t shift = 0;
    int i = 0;

    len = (1 << prefix);
    if (len > blen) {
        return -1;
    }
    var = (void *)buf;
    var->prefix = prefix;
    shift = (len - 1) * 8;
    var->value = (length >> shift) & 0x3F;
    for (i = 1; i < len; i++) {
        shift = (len - i - 1)*8;
        buf[i] = (length >> shift) & 0xFF;
    }

    return 0;
}

int QuicVariableLengthEncode(uint8_t *buf, size_t blen, uint64_t length)
{
    uint8_t prefix = 0;

    if ((length >> 62) > 0) {
        return -1;
    }

    for (prefix = 3; prefix > 0; prefix--) {
        if ((length >> ((1 << (prefix - 1))*8 - 2)) > 0) {
            break;
        }
    }

    return QuicVariableLengthValueEncode(buf, blen, length, prefix);
}

int QuicVariableLengthDecode(RPacket *pkt, uint64_t *length)
{
    QuicVarLenFirstByte var = {};
    uint8_t prefix = 0;
    uint8_t v = 0;
    uint8_t len = 0;
    int i = 0;

    if (RPacketGet1(pkt,  &var.var) < 0) {
        return -1;
    }

    prefix = var.prefix;
    len = 1 << prefix;

    *length = var.value;

    for (i = 1; i < len; i++) {
        if (RPacketGet1(pkt,  &v) < 0) {
            return -1;
        }
        *length = (*length << 8) + v;
    }

    return 0;
}

static int QuicPacketHeaderParse(Packet *pkt)
{
    if (RPacketGet4(&pkt->frame,  &pkt->version) < 0) {
        return -1;
    }

    if (RPacketGet1(&pkt->frame,  &pkt->dest_conn_id_len) < 0) {
        return -1;
    }

    if (pkt->dest_conn_id_len == 0) {
        return -1;
    }

    pkt->dest_conn_id = RPacketData(&pkt->frame);
    RPacketForward(&pkt->frame, pkt->dest_conn_id_len);

    if (RPacketGet1(&pkt->frame,  &pkt->source_conn_id_len) < 0) {
        return -1;
    }

    if (pkt->source_conn_id_len != 0) {
        pkt->source_conn_id = RPacketData(&pkt->frame);
        RPacketForward(&pkt->frame, pkt->source_conn_id_len);
    }

    return 0;
}

static int QuicInitPacketHandler(Packet *pkt)
{
    int pkt_num_len = 0;

    if (QuicPacketHeaderParse(pkt) < 0) {
        return -1;
    }

    pkt_num_len = pkt->flags & QUIC_LPACKET_PKT_NUM_LEN_MASK;
    printf("IIIint, pkt_num_len = %d\n", pkt_num_len);

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

