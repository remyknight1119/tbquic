#ifndef TBQUIC_QUIC_FORMAT_H_
#define TBQUIC_QUIC_FORMAT_H_

#include <stdint.h>
#include <stdbool.h>

#include <tbquic/types.h>

#include "packet_local.h"
#include "base.h"
#include "q_buff.h"

#define QUIC_PKT_NUM_MAX (0x3FFFFFFFFFFFFFFF) //2^62 - 1
#define QUIC_INITIAL_PKT_DATAGRAM_SIZE_MIN      1200

#define QUIC_LPACKET_TYPE_INITIAL 	    0x00
#define QUIC_LPACKET_TYPE_0RTT 	        0x01
#define QUIC_LPACKET_TYPE_HANDSHAKE 	0x02
#define QUIC_LPACKET_TYPE_RETRY 		0x03

#define QUIC_LPACKET_TYPE_RESV_MASK 	0x0F
#define QUIC_SPACKET_TYPE_RESV_MASK 	0x1F

/*
 * Although the QUIC SCID/DCID length field can store at most 255, v1 limits the
 * CID length to 20.
 */
#define QUIC_MAX_CID_LENGTH     20
//RFC 9000 7.2. Negotiating Connection IDs
#define QUIC_MIN_CID_LENGTH     8
#define QUIC_SAMPLE_LEN     16
#define QUIC_PACKET_NUM_MAX_LEN     4
#define QUIC_VARIABLE_LEN_MAX_SIZE  8

#define QUIC_PACKET_IS_LONG_PACKET(flags) (flags.h.header_form)

enum {
    QUIC_PKT_TYPE_INITIAL,
    QUIC_PKT_TYPE_0RTT,
    QUIC_PKT_TYPE_HANDSHAKE,
    QUIC_PKT_TYPE_RETRY,
    QUIC_PKT_TYPE_1RTT,
    QUIC_PKT_TYPE_MAX,
};

typedef int (*QuicPacketParse)(QUIC *quic, RPacket *pkt, QUIC_CRYPTO *c);

typedef union {
    uint8_t value;
    struct {
        uint8_t packet_num_len:2;
        uint8_t reserved:2;
        uint8_t lpacket_type:2;
        uint8_t fixed:1;
        uint8_t header_form:1;
    } lh;
    struct {
        uint8_t packet_num_len:2;
        uint8_t key_phase:1;
        uint8_t reserved:2;
        uint8_t spin:1;
        uint8_t fixed:1;
        uint8_t header_form:1;
    } sh;
    struct {
        uint8_t others:6;
        uint8_t fixed:1;
        uint8_t header_form:1;
    } h;
} QuicPacketFlags;

typedef union {
    uint8_t var;
    struct {
        uint8_t value:6;
        uint8_t prefix:2;
    };
} QuicVarLenFirstByte;

int QuicVariableLengthEncode(uint8_t *, size_t , uint64_t);
int QuicVariableLengthDecode(RPacket *, uint64_t *);
int QuicVariableLengthWrite(WPacket *, uint64_t);
int QuicVariableLengthValueWrite(WPacket *, uint64_t);
uint32_t QuicPktNumberEncode(uint64_t, uint64_t, uint8_t);
uint64_t QuicPktNumberDecode(uint64_t, uint32_t, uint8_t);
int QuicLPacketHeaderParse(QUIC *, RPacket *, QUIC_DATA *, bool *);
int QuicSPacketHeaderParse(QUIC *, RPacket *);
int QuicUpdateDcid(QUIC *, QUIC_DATA *, uint32_t);
int QuicPktHeaderParse(QUIC *, RPacket *, QuicPacketFlags, uint32_t *,
                        QUIC_DATA *, bool *);
int QuicPktBodyParse(QUIC *, RPacket *, uint32_t);
int QuicInitPacketParse(QUIC *, RPacket *, QUIC_CRYPTO *);
size_t QuicInitialPacketGetTotalLen(QUIC *, size_t);
size_t QuicHandshakePacketGetTotalLen(QUIC *, size_t);
size_t QuicAppDataPacketGetTotalLen(QUIC *, size_t);
int QuicInitialPacketBuild(QUIC *, WPacket *, QBUFF *, bool);
int QuicHandshakePacketBuild(QUIC *, WPacket *, QBUFF *, bool);
int QuicAppDataPacketBuild(QUIC *, WPacket *, QBUFF *, bool);
void QuicAddQueue(QUIC *quic, QBUFF *qb);
int QuicWPacketSubMemcpyVar(WPacket *, const void *, size_t);
int QuicClntParseScid(QUIC *quic, RPacket *pkt, size_t);
int QuicClntParseDcid(QUIC *quic, RPacket *pkt, size_t);
int QuicSrvrParseScid(QUIC *quic, RPacket *pkt, size_t);
int QuicSrvrParseDcid(QUIC *quic, RPacket *pkt, size_t);
int QuicGetPktFlags(QuicPacketFlags *, RPacket *);
int QuicGetDcidFromPkt(QUIC_DATA *, const uint8_t *, size_t);

#ifdef QUIC_TEST
extern void (*QuicEncryptPayloadHook)(QBUFF *qb);
#endif

#endif
