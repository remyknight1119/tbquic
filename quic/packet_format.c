/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_format.h"

#include "common.h"

static int QuicInitPacketPaser(Packet *, QuicLPacketFlags);
static int Quic0RttPacketPaser(Packet *, QuicLPacketFlags);
static int QuicHandshakePacketPaser(Packet *, QuicLPacketFlags);
static int QuicRetryPacketPaser(Packet *, QuicLPacketFlags);

static QuicLongPacketParse LPacketPaser[] = {
    {
        .type = QUIC_LPACKET_TYPE_INITIAL,
        .parser = QuicInitPacketPaser,
    },
    {
        .type = QUIC_LPACKET_TYPE_0RTT,
        .parser = Quic0RttPacketPaser,
    },
    {
        .type = QUIC_LPACKET_TYPE_HANDSHAKE,
        .parser = QuicHandshakePacketPaser,
    },
    {
        .type = QUIC_LPACKET_TYPE_RETRY,
        .parser = QuicRetryPacketPaser,
    },
};

#define LPACKET_PARSER_NUM     QUIC_ARRAY_SIZE(LPacketPaser) 

static int QuicLongPacketDoParse(Packet *pkt)
{
    QuicLPacketFlags lflags;
    uint8_t type = 0;
    int i = 0;

    lflags.value = pkt->flags;
    type = lflags.lpacket_type;
    for (i = 0; i < LPACKET_PARSER_NUM; i++) {
        if (LPacketPaser[i].type == type) {
            return LPacketPaser[i].parser(pkt, lflags);
        }
    }

    return -1;
}

static int QuicShortPacketDoParse(Packet *pkt)
{
    return -1;
}

int QuicPacketParse(Packet *pkt)
{
    QuicPacketFlags pflags;

    pflags.value = pkt->flags;
    printf("f = %d, s = %d\n", pflags.header_form, (int)sizeof(pflags));
    if (QUIC_PACKET_IS_LONG_PACKET(pflags)) {
        return QuicLongPacketDoParse(pkt);
    }

    return QuicShortPacketDoParse(pkt);
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

static int QuicInitPacketPaser(Packet *pkt, QuicLPacketFlags flags)
{
    int pkt_num_len = 0;

    if (QuicPacketHeaderParse(pkt) < 0) {
        return -1;
    }

    pkt_num_len = flags.packet_num_len;
    printf("IIIint, pkt_num_len = %d\n", pkt_num_len);

    return 0;
}

static int Quic0RttPacketPaser(Packet *pkt, QuicLPacketFlags flags)
{
    return 0;
}

static int QuicHandshakePacketPaser(Packet *pkt, QuicLPacketFlags flags)
{
    return 0;
}

static int QuicRetryPacketPaser(Packet *pkt, QuicLPacketFlags flags)
{
    return 0;
}

