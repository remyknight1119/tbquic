#ifndef TBQUIC_QUIC_STREAM_H_
#define TBQUIC_QUIC_STREAM_H_

#include <stdint.h>

#include <tbquic/types.h>
#include "list.h"

#define QUIC_STREAM_INITIATED_BY_SERVER     0x01
#define QUIC_STREAM_UNIDIRECTIONAL          0x02
#define QUIC_STREAM_ID_MASK                 0x03
#define QUIC_STREAM_ID_MASK_BITS            2

#define QUIC_STREAM_CLIENT_INITIATED_BIDIRECTIONAL 	    0
#define QUIC_STREAM_SERVER_INITIATED_BIDIRECTIONAL 	\
            QUIC_STREAM_INITIATED_BY_SERVER
#define QUIC_STREAM_CLIENT_INITIATED_UNIDIRECTIONAL \
            QUIC_STREAM_UNIDIRECTIONAL
#define QUIC_STREAM_SERVER_INITIATED_UNIDIRECTIONAL \
            (QUIC_STREAM_INITIATED_BY_SERVER|QUIC_STREAM_UNIDIRECTIONAL)

enum {
	QUIC_STREAM_STATE_START = 0,
	QUIC_STREAM_STATE_READY,
	QUIC_STREAM_STATE_SEND,
	QUIC_STREAM_STATE_RECV,
	QUIC_STREAM_STATE_SIZE_KNOWN,
	QUIC_STREAM_STATE_DATA_SENT,
	QUIC_STREAM_STATE_RESET_SENT,
	QUIC_STREAM_STATE_DATA_RECVD,
	QUIC_STREAM_STATE_RESET_RECVD,
	QUIC_STREAM_STATE_DATA_READ,
	QUIC_STREAM_STATE_RESET_READ,
	QUIC_STREAM_STATE_MAX,
};

typedef struct {
    uint64_t id_alloced;
    uint64_t bidi_id_num_limit;
    uint64_t uni_id_num_limit;
    struct list_head queue; 
} QuicStreamConf;

typedef struct QuicStreamIns {
    struct list_head node; 
    uint64_t id;
    uint32_t mode:2;
    uint32_t recv_state;
    uint32_t send_state;
    void *quic;
} QuicStreamInstance;

void QuicStreamConfInit(QUIC *);
void QuicStreamQueueDestroy(QuicStreamConf *scf);

#endif
