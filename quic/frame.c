/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "frame.h"

#include <string.h>

#include "common.h"
#include "log.h"
#include "format.h"
#include "quic_local.h"
#include "buffer.h"


static int QuicFrameCryptoParser(QUIC *quic, RPacket *pkt);
static int QuicFramePingParser(QUIC *quic, RPacket *pkt);
static int QuicFrameAckParser(QUIC *quic, RPacket *pkt);
static int QuicFrameStreamParser(QUIC *quic, RPacket *pkt);

static QuicFrameParser frame_parser[QUIC_FRAME_TYPE_MAX] = {
    [QUIC_FRAME_TYPE_CRYPTO] = QuicFrameCryptoParser,
    [QUIC_FRAME_TYPE_PING] = QuicFramePingParser,
    [QUIC_FRAME_TYPE_ACK] = QuicFrameAckParser,
    [QUIC_FRAME_TYPE_STREAM] = QuicFrameStreamParser,
};

int QuicFrameDoParser(QUIC *quic, RPacket *pkt)
{
    QuicFrameParser parser = NULL;
    uint64_t type = 0;

    while (QuicVariableLengthDecode(pkt, &type) >= 0) {
        if (type >= QUIC_FRAME_TYPE_MAX) {
            QUIC_LOG("Unknown type(%lx)", type);
            return -1;
        }
        parser = frame_parser[type];
        if (parser == NULL) {
            continue;
        }

        if (parser(quic, pkt) < 0) {
            return -1;
        }
    }

    return 0;
}

static int QuicFrameCryptoParser(QUIC *quic, RPacket *pkt)
{
    QUIC_BUFFER *buf = QUIC_TLS_BUFFER(quic);
    uint8_t *data = NULL;
    uint64_t offset = 0;
    uint64_t length = 0;
    uint64_t total_len = 0;

    if (QuicVariableLengthDecode(pkt, &offset) < 0) {
        QUIC_LOG("Offset decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &length) < 0) {
        QUIC_LOG("Length decode failed!\n");
        return -1;
    }

    total_len = offset + length;
    if (QUIC_GT(total_len, QuicBufLength(buf))) {
        if (QuicBufMemGrow(buf, total_len) == 0) {
            QUIC_LOG("Buffer grow failed!\n");
            return -1;
        }
    }

    data = QuicBufData(buf);
    if (data == NULL) {
        QUIC_LOG("Get buffer data failed!\n");
        return -1;
    }

    if (offset == 0) {
    }

    if (RPacketCopyBytes(pkt, &data[offset], length) < 0) {
        QUIC_LOG("Copy PKT data failed!\n");
        return -1;
    }

    if (QUIC_GT(total_len, QuicBufGetDataLength(buf))) {
        QuicBufSetDataLength(buf, total_len);
    }

    return 0;
}

static int QuicFramePingParser(QUIC *quic, RPacket *pkt)
{
    return 0;
}

static int QuicFrameAckParser(QUIC *quic, RPacket *pkt)
{
    uint64_t largest_acked = 0;
    uint64_t ack_delay = 0;
    uint64_t range_count = 0;
    uint64_t first_ack_range = 0;
    uint64_t gap = 0;
    uint64_t ack_range_len = 0;
    uint64_t i = 0;

    if (QuicVariableLengthDecode(pkt, &largest_acked) < 0) {
        QUIC_LOG("Offset decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &ack_delay) < 0) {
        QUIC_LOG("Offset decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &range_count) < 0) {
        QUIC_LOG("Offset decode failed!\n");
        return -1;
    }

    if (QuicVariableLengthDecode(pkt, &first_ack_range) < 0) {
        QUIC_LOG("Offset decode failed!\n");
        return -1;
    }

    for (i = 0; i < range_count; i++) {
        if (QuicVariableLengthDecode(pkt, &gap) < 0) {
            QUIC_LOG("Offset decode failed!\n");
            return -1;
        }

        if (QuicVariableLengthDecode(pkt, &ack_range_len) < 0) {
            QUIC_LOG("Offset decode failed!\n");
            return -1;
        }
    }

    return 0;
}

static int QuicFrameStreamParser(QUIC *quic, RPacket *pkt)
{
    const uint8_t *data = NULL;
    size_t data_len = 0;
    uint64_t id = 0;

    if (QuicVariableLengthDecode(pkt, &id) < 0) {
        QUIC_LOG("ID decode failed!\n");
        return -1;
    }

    data_len = RPacketRemaining(pkt);
    if (RPacketGetBytes(pkt, &data, data_len) < 0) {
        QUIC_LOG("Peek stream data failed!\n");
        return -1;
    }

    QuicPrint(data, data_len);
    return 0;
}

int QuicFramePaddingBuild(WPacket *pkt, size_t len)
{
    return WPacketMemset(pkt, 0, len);
}

int QuicFramePingBuild(WPacket *pkt)
{
    return WPacketPut1(pkt, QUIC_FRAME_TYPE_PING);
}

int QuicFrameCryptoComputeLen(uint64_t offset, size_t len)
{
    uint64_t vlen = 0;
    int owlen = 0;
    int lwlen = 0;

    owlen = QuicVariableLengthEncode((uint8_t *)&vlen, sizeof(vlen), offset);
    if (owlen < 0) {
        return -1;
    }

    lwlen = QuicVariableLengthEncode((uint8_t *)&vlen, sizeof(vlen), len);
    if (lwlen < 0) {
        return -1;
    }

    return 1 + owlen + lwlen + len;
}

int QuicFrameCryptoBuild(WPacket *pkt, uint64_t offset,
                            uint8_t *data, size_t len)
{
    if (WPacketPut1(pkt, QUIC_FRAME_TYPE_CRYPTO) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, offset) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, len) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, data, len);
}

