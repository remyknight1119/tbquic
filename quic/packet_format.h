#ifndef TBQUIC_QUIC_PACKET_FORMAT_H_
#define TBQUIC_QUIC_PACKET_FORMAT_H_

#include <stdint.h>
#include <stdbool.h>

#include "packet_local.h"

#define QUIC_PACKET_HEADER_FORM_LPACKET     0x80
#define QUIC_PACKET_HEADER_FIXED            0x40
#define QUIC_PACKET_HEADER_SPIN             0x04
#define QUIC_PACKET_HEADER_KEY_PHASE        0x20
#define QUIC_PACKET_LPACKET_TYPE_MASK       0x30
#define QUIC_LPACKET_PKT_NUM_LEN_MASK       0x03

#define QUIC_LPACKET_TYPE_INITIAL 	    0x00
#define QUIC_LPACKET_TYPE_0RTT 	        0x01
#define QUIC_LPACKET_TYPE_HANDSHAKE 	0x02
#define QUIC_LPACKET_TYPE_RETRY 		0x03

#define QUIC_PACKET_IS_LONG_PACKET(flags) \
    (flags & QUIC_PACKET_HEADER_FORM_LPACKET)
#define QUIC_PACKET_HEADER_GET_TYPE(flags) \
    ((flags & QUIC_PACKET_LPACKET_TYPE_MASK) >> 2)
#define QUIC_PACKET_HEADER_GET_PKE_NUM_LEN(flags) \
    ((flags & QUIC_PACKET_LPACKET_PLT_NUM_LEN_MASK) >> 6)

typedef int (*QuicPacketHandler)(Packet *);

typedef struct LongPacketProcess {
    uint8_t type;
    QuicPacketHandler handler;
} QuicLongPacketProcess;

typedef union {
    uint8_t var;
    struct {
        uint8_t prefix:2;
        uint8_t value:6;
    };
} QuicVarLenFirstByte;


bool QuicIsLittleEndianBitOrder(void);
QuicPacketHandler QuicPacketHandlerFind(uint8_t);
int QuicVariableLengthEncode(uint8_t *buf, size_t blen, uint64_t length);
int QuicVariableLengthDecode(RPacket *pkt, uint64_t *length);

#endif
