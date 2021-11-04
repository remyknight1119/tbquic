#ifndef TBQUIC_QUIC_PACKET_FORMAT_H_
#define TBQUIC_QUIC_PACKET_FORMAT_H_

#include <stdint.h>
#include <stdbool.h>

#include <tbquic/types.h>

#include "packet_local.h"

#define QUIC_LPACKET_TYPE_INITIAL 	    0x00
#define QUIC_LPACKET_TYPE_0RTT 	        0x01
#define QUIC_LPACKET_TYPE_HANDSHAKE 	0x02
#define QUIC_LPACKET_TYPE_RETRY 		0x03

#define QUIC_PACKET_IS_LONG_PACKET(flags) (flags.header_form)

typedef union LPacketFlags QuicLPacketFlags; 
typedef int (*QuicLPacketPaser)(QUIC *, RPacket *, QuicLPacketFlags);

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

typedef struct {
	uint8_t flags;
	uint8_t	dest_conn_id_len;
	uint8_t	source_conn_id_len;
    const uint8_t *dest_conn_id;
    const uint8_t *source_conn_id;
    uint32_t version;
    uint32_t pkt_num;
    uint64_t token_len;
    const uint8_t *token;
} LPacketHeader;

int QuicPacketParse(QUIC *quic, RPacket *pkt, uint8_t flags);
int QuicVariableLengthEncode(uint8_t *buf, size_t blen, uint64_t length);
int QuicVariableLengthDecode(RPacket *pkt, uint64_t *length);

#endif
