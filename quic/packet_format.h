#ifndef TBQUIC_QUIC_PACKET_FORMAT_H_
#define TBQUIC_QUIC_PACKET_FORMAT_H_

#include <stdint.h>
#include <stdbool.h>

#include "packet_local.h"

#define QUIC_LPACKET_TYPE_INITIAL 	    0x00
#define QUIC_LPACKET_TYPE_0RTT 	        0x01
#define QUIC_LPACKET_TYPE_HANDSHAKE 	0x02
#define QUIC_LPACKET_TYPE_RETRY 		0x03

#define QUIC_PACKET_IS_LONG_PACKET(flags) (flags.header_form)

typedef union LPacketFlags QuicLPacketFlags; 
typedef int (*QuicLPacketPaser)(Packet *, QuicLPacketFlags);

typedef struct {
    uint8_t type;
    QuicLPacketPaser parser;
} QuicLongPacketParse;

typedef union {
    uint8_t value;
    struct {
        uint8_t other_filed:6;
        uint8_t fixed_bit:1;
        uint8_t header_form:1;
    };
} QuicPacketFlags;

union LPacketFlags {
    uint8_t value;
    struct {
        uint8_t packet_num_len:2;
        uint8_t reserved_bits:2;
        uint8_t lpacket_type:2;
        uint8_t fixed_bit:1;
        uint8_t header_form:1;
    };
};

typedef union {
    uint8_t var;
    struct {
        uint8_t value:6;
        uint8_t prefix:2;
    };
} QuicVarLenFirstByte;

int QuicPacketParse(Packet *pkt);
int QuicVariableLengthEncode(uint8_t *buf, size_t blen, uint64_t length);
int QuicVariableLengthDecode(RPacket *pkt, uint64_t *length);

#endif
