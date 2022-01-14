/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_test.h"

#include <tbquic/quic.h>

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "format.h"
#include "packet_local.h"
#include "common.h"

int QuicVariableLengthDecodeTest(void)
{
    RPacket pkt;
    uint8_t a = 0x25;
    uint16_t b = 0x7bbd;
    uint32_t c = 0x9d7f3e7d;
    uint64_t d = 0xc2197c5eff14e88c;
    uint64_t len = 0;

    QuicVariableLengthEncode(&a, sizeof(a), 0x25);
    RPacketBufInit(&pkt, &a, sizeof(a));
    QuicVariableLengthDecode(&pkt, &len);
    if (len != 37) {
        printf("byte len = %lu\n", len);
        return -1;
    }
    QuicVariableLengthEncode((uint8_t *)&b, sizeof(b), 15293);
    RPacketBufInit(&pkt, (uint8_t *)&b, sizeof(b));
    QuicVariableLengthDecode(&pkt, &len);
    if (len != 15293) {
        printf("short len = %lu\n", len);
        return -1;
    }
    QuicVariableLengthEncode((uint8_t *)&c, sizeof(c), 494878333);
    RPacketBufInit(&pkt, (uint8_t *)&c, sizeof(c));
    QuicVariableLengthDecode(&pkt, &len);
    if (len != 494878333) {
        printf("uint len = %lu\n", len);
        return -1;
    }

    QuicVariableLengthEncode((uint8_t *)&d, sizeof(d), 151288809941952652);
    RPacketBufInit(&pkt, (uint8_t *)&d, sizeof(d));
    QuicVariableLengthDecode(&pkt, &len);
    if (len != 151288809941952652) {
        printf("ulong len = %lu\n", len);
        return -1;
    }

    return 4;
}

int QuicPktNumberEncodeTest(void)
{
    uint64_t curr_num = 0xa82f30ea;
    uint64_t full_pn = 0xa82f9b32;
    uint32_t value = 0x9b32;
    uint32_t encode = 0;

    QuicPktNumberEncode(0xac5c02, 0xabe8b3, 32);
    QuicPktNumberEncode(0xace8fe, 0xabe8b3, 32);
    encode = QuicPktNumberEncode(full_pn, curr_num, 16);
    if (encode != value) {
        return -1;
    }

    return 1;
}

int QuicPktNumberDecodeTest(void)
{
    uint64_t curr_num = 0xa82f30ea;
    uint64_t num = 0;
    uint64_t result = 0xa82f9b32;
    uint32_t value = 0x9b32;

    num = QuicPktNumberDecode(curr_num, value, 16);
    if (num != result) {
        return -1;
    }

    return 1;
}

static int QuicVerifyVarData(uint8_t *data, size_t total_len, int wlen)
{
    RPacket pkt = {};
    uint64_t len = 0;

    RPacketBufInit(&pkt, data, total_len);
    if (QuicVariableLengthDecode(&pkt, &len) < 0) {
        return -1;
    }

    if (len != RPacketRemaining(&pkt)) {
        printf("len not match(%lu, %lu)\n", len, RPacketRemaining(&pkt));
        return -1;
    }

    if (len != wlen) {
        printf("wlen not match(%lu, %d)\n", len, wlen);
        return -1;
    }

    return 0;
}

#define SUB_MEMCPY_VAR_BUF_LEN  65535
int QuicWPacketSubMemcpyVarTest(void)
{
    WPacket pkt = {};
    size_t size = 0;
    static uint8_t buf[SUB_MEMCPY_VAR_BUF_LEN] = {};
    static uint8_t data[SUB_MEMCPY_VAR_BUF_LEN + 5] = {};
    int wlen = 0;

    memset(data, 0x1, sizeof(data));

    size = sizeof(buf);
    WPacketStaticBufInit(&pkt, buf, size);
    wlen = QuicWPacketSubMemcpyVar(&pkt, data, sizeof(data));
    if (wlen < 0) {
        return -1;
    }

    if (QuicVerifyVarData(buf, WPacket_get_written(&pkt), wlen) < 0) {
        return -1;
    }

    return 1;
}

