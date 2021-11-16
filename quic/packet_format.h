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

/*
 * Although the QUIC SCID/DCID length field can store at most 255, v1 limits the
 * CID length to 20.
 */
#define QUIC_MAX_CID_LENGTH     20
//RFC 9000 7.2. Negotiating Connection IDs
#define QUIC_MIN_CID_LENGTH     8
#define QUIC_SAMPLE_LEN     16
#define QUIC_MACKET_NUM_MAX_LEN     4

#define QUIC_PACKET_IS_LONG_PACKET(flags) (flags.header_form)

typedef struct LPacketHeader QuicLPacketHeader;
typedef int (*QuicLPacketPaser)(QUIC *, RPacket *, QuicLPacketHeader *);

typedef struct {
    uint8_t type;
    uint32_t min_version;
    uint32_t max_version;
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

typedef union {
    uint8_t value;
    struct {
        uint8_t packet_num_len:2;
        uint8_t reserved_bits:2;
        uint8_t lpacket_type:2;
        uint8_t fixed_bit:1;
        uint8_t header_form:1;
    };
} QuicLPacketFlags;

typedef union {
    uint8_t var;
    struct {
        uint8_t value:6;
        uint8_t prefix:2;
    };
} QuicVarLenFirstByte;

struct LPacketHeader {
    QuicLPacketFlags flags;
	uint8_t	dest_conn_id_len;
	uint8_t	source_conn_id_len;
    const uint8_t *dest_conn_id;
    const uint8_t *source_conn_id;
    uint8_t pkt_num_len;
    uint32_t version;
    uint32_t pkt_num;
    uint64_t token_len;
    const uint8_t *token;
};

int QuicPacketParse(QUIC *, RPacket *, uint8_t);
int QuicVariableLengthEncode(uint8_t *, size_t , uint64_t);
int QuicVariableLengthDecode(RPacket *, uint64_t *);
uint64_t QuicPktNumberDecode(uint64_t, uint32_t, uint8_t);

#endif
