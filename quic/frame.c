/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "frame.h"

#include <string.h>

#include "common.h"
#include "log.h"
#include "packet_format.h"
#include "quic_local.h"
#include "buffer.h"


static int QuicFrameCryptoParser(QUIC *quic, RPacket *pkt);
static int QuicFramePingParser(QUIC *quic, RPacket *pkt);

static QuicFrameParser frame_parser[QUIC_FRAME_TYPE_MAX] = {
    [QUIC_FRAME_TYPE_CRYPTO] = QuicFrameCryptoParser,
    [QUIC_FRAME_TYPE_PING] = QuicFramePingParser,
};

int QuicFrameDoParser(QUIC *quic, RPacket *pkt)
{
    QuicFrameParser parser = NULL;
    uint64_t type = 0;

    while (QuicVariableLengthDecode(pkt, &type) >= 0) {
        if (type >= QUIC_FRAME_TYPE_MAX) {
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
    QUIC_BUFFER *buf = &quic->tls.buffer;
    uint8_t *data = NULL;
    uint64_t offset = 0;
    uint64_t length = 0;
    uint64_t total_len = 0;

    if (QuicVariableLengthDecode(pkt, &offset) < 0) {
        QUIC_LOG("Offset decodd failed!\n");
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

    if (RPacketCopyBytes(pkt, &data[offset], length) < 0) {
        QUIC_LOG("Copy PKT data failed!\n");
        return -1;
    }

    if (QUIC_GT(total_len, buf->data_len)) {
        buf->data_len = total_len;
    }

    printf("Crypto offset = %lu length = %lu\n", offset, length);
    return 0;
}

static int QuicFramePingParser(QUIC *quic, RPacket *pkt)
{
    return 0;
}

int QuicFramePaddingBuild(WPacket *pkt, size_t len)
{
    uint8_t *dest;

    if (len == 0) {
        return 0;
    }

    if (WPacketAllocateBytes(pkt, len, &dest) < 0) {
        return -1;
    }

    memset(dest, QUIC_FRAME_TYPE_PADDING, len);

    return 0;
}

int QuicFramePingBuild(WPacket *pkt)
{
    return WPacketPut1(pkt, QUIC_FRAME_TYPE_PING);
}

int QuicFrameCryptoBuild(QUIC *quic, WPacket *pkt)
{
    QUIC_BUFFER *crypto_buf = QUIC_TLS_BUFFER(quic);
    uint64_t offset = 0;

    if (crypto_buf->data_len == 0) {
        return 0;
    }

    if (WPacketPut1(pkt, QUIC_FRAME_TYPE_CRYPTO) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, offset) < 0) {
        return -1;
    }

    if (QuicVariableLengthWrite(pkt, crypto_buf->data_len) < 0) {
        return -1;
    }

    return WPacketMemcpy(pkt, QUIC_BUFFER_HEAD(crypto_buf),
                            crypto_buf->data_len);
}

