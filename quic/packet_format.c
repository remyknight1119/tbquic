/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "packet_format.h"

#include <string.h>
#include <arpa/inet.h>

#include "common.h"
#include "mem.h"
#include "quic_local.h"

static int QuicInitPacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);
static int Quic0RttPacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);
static int QuicHandshakePacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);
static int QuicRetryPacketPaser(QUIC *, RPacket *, QuicLPacketHeader *);

static QuicLongPacketParse LPacketPaser[] = {
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_INITIAL,
        .parser = QuicInitPacketPaser,
    },
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_0RTT,
        .parser = Quic0RttPacketPaser,
    },
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_HANDSHAKE,
        .parser = QuicHandshakePacketPaser,
    },
    {
        .min_version = QUIC_VERSION_1,
        .max_version = QUIC_VERSION_1,
        .type = QUIC_LPACKET_TYPE_RETRY,
        .parser = QuicRetryPacketPaser,
    },
};

#define LPACKET_PARSER_NUM     QUIC_ARRAY_SIZE(LPacketPaser) 

static int QuicLPacketHeaderParse(QUIC *quic, QuicLPacketHeader *h, RPacket *pkt)
{
    uint32_t version = 0;
    uint32_t len = 0;

    if (RPacketGet4(pkt, &version) < 0) {
        return -1;
    }

    h->version = ntohl(version);

    if (RPacketGet1(pkt, &len) < 0) {
        return -1;
    }

    if ((h->version == QUIC_VERSION_1 && len > QUIC_MAX_CID_LENGTH) ||
            len == 0) {
        return -1;
    }

    h->dest_conn_id_len = len;
    h->dest_conn_id = RPacketData(pkt);
    RPacketForward(pkt, h->dest_conn_id_len);

    if (RPacketGet1(pkt,  &len) < 0) {
        return -1;
    }

    h->source_conn_id_len = len;
    if (h->source_conn_id_len != 0) {
        h->source_conn_id = RPacketData(pkt);
        RPacketForward(pkt, h->source_conn_id_len);
    }

    return 0;
}

static int QuicLongPacketDoParse(QUIC *quic, RPacket *pkt, uint8_t flags)
{
    QuicLongPacketParse *p = NULL;
    QuicLPacketHeader h = {};
    uint32_t version = 0;
    uint8_t type = 0;
    int i = 0;

    if (QuicLPacketHeaderParse(quic, &h, pkt) < 0) {
        return -1;
    }

    version = h.version;
    h.flags.value = flags;
    type = h.flags.lpacket_type;
    for (i = 0; i < LPACKET_PARSER_NUM; i++) {
        p = &LPacketPaser[i];
        if (p->type == type && p->min_version <= version &&
                version <= p->max_version) {
            return p->parser(quic, pkt, &h);
        }
    }

    return -1;
}

static int QuicShortPacketDoParse(QUIC *quic, RPacket *pkt, uint8_t flags)
{
    return -1;
}

int QuicPacketParse(QUIC *quic, RPacket *pkt, uint8_t flags)
{
    QuicPacketFlags pflags;

    pflags.value = flags;
    if (QUIC_PACKET_IS_LONG_PACKET(pflags)) {
        return QuicLongPacketDoParse(quic, pkt, flags);
    }

    return QuicShortPacketDoParse(quic, pkt, flags);
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
    uint8_t len = 0;
    uint32_t v = 0;
    int i = 0;

    if (RPacketGet1(pkt,  &v) < 0) {
        return -1;
    }

    var.var = v;
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

static int QuicInitPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    uint64_t token_len = 0;
    uint64_t length = 0;
    int pkt_num_len = 0;

    if (quic->peer_dcid.cid != NULL) {
        return -1;
    }

    quic->peer_dcid.cid = QuicMemMalloc(h->dest_conn_id_len);
    if (quic->peer_dcid.cid == NULL) {
        return -1;
    }
    quic->peer_dcid.len = h->dest_conn_id_len;
    memcpy(quic->peer_dcid.cid, h->dest_conn_id, quic->peer_dcid.len);
 
    if (QuicVariableLengthDecode(pkt, &token_len) < 0) {
        return -1;
    }

    if (token_len != 0) {
        //token = RPacketData(pkt);
        RPacketForward(pkt, token_len);
    }

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        return -1;
    }

    if (length != RPacketRemaining(pkt)) {
        printf("length(%lu) not match remaining(%lu)!\n", length, RPacketRemaining(pkt));
        return -1;
    }

    pkt_num_len = h->flags.packet_num_len;
    printf("IIIint, f = %x, pkt_num_len = %d, r = %d\n", h->flags.value, pkt_num_len, h->flags.reserved_bits);

    return 0;
}

static int Quic0RttPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    return 0;
}

static int QuicHandshakePacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    return 0;
}

static int QuicRetryPacketPaser(QUIC *quic, RPacket *pkt, QuicLPacketHeader *h)
{
    return 0;
}

