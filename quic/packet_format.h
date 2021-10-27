#ifndef TBQUIC_QUIC_PACKET_FORMAT_H_
#define TBQUIC_QUIC_PACKET_FORMAT_H_

#include <stdint.h>

#define TBQUIC_PACKET_HEADER_FORM_LPACKET 		0x01
#define TBQUIC_PACKET_HEADER_FIXED              0x02
#define TBQUIC_PACKET_HEADER_SPIN               0x04
#define TBQUIC_PACKET_HEADER_KEY_PHASE 			0x20
#define TBQUIC_PACKET_LPACKET_TYPE_MASK 		0x0c
#define TBQUIC_PACKET_LPACKET_PLT_NUM_LEN_MASK 	0xc0

#define LPACKET_TYPE_INITIAL 	0x00
#define LPACKET_TYPE_0RTT 		0x01
#define LPACKET_TYPE_HANDSHAKE 	0x02
#define LPACKET_TYPE_RETRY 		0x03

#define TBQUIC_PACKET_HEADER_GET_TYPE(type) \
    ((type & TBQUIC_PACKET_LPACKET_TYPE_MASK) >> 2)
#define TBQUIC_PACKET_HEADER_GET_PKE_NUM_LEN(type) \
    ((type & TBQUIC_PACKET_LPACKET_PLT_NUM_LEN_MASK) >> 6)

typedef struct __attribute__ ((__packed__)) QuicPacketHeader {
	uint8_t 	flags;
	uint32_t 	version;
	uint8_t 	dest_conn_id_len;
	/* Destination Connection ID (0..160) */
	/* Source Connection ID Length (8) */
	/* Source Connection ID (0..160) */
	/* Type-Specific Payload (..) */
} QuicPacketHeader;

#endif
