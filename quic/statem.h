#ifndef TBQUIC_QUIC_STATEM_H_
#define TBQUIC_QUIC_STATEM_H_

#include <stddef.h>
#include <tbquic/types.h>

#include "packet_local.h"

#define QUIC_STREAM_INITIATED_BY_SERVER     0x01
#define QUIC_STREAM_UNIDIRECTIONAL          0x02

#define QUIC_STREAM_CLIENT_INITIATED_BIDIRECTIONAL 	    0
#define QUIC_STREAM_SERVER_INITIATED_BIDIRECTIONAL 	    QUIC_STREAM_INITIATED_BY_SERVER
#define QUIC_STREAM_CLIENT_INITIATED_UNIDIRECTIONAL     QUIC_STREAM_UNIDIRECTIONAL
#define QUIC_STREAM_SERVER_INITIATED_UNIDIRECTIONAL     (QUIC_STREAM_INITIATED_BY_SERVER|QUIC_STREAM_UNIDIRECTIONAL)

typedef enum {
	QUIC_STREAM_STATE_READY = 0,
	QUIC_STREAM_STATE_SEND,
	QUIC_STREAM_STATE_RECV,
	QUIC_STREAM_STATE_SIZE_KNOWN,
	QUIC_STREAM_STATE_DATA_SEND,
	QUIC_STREAM_STATE_DATA_RECVD,
	QUIC_STREAM_STATE_RECV_DATA_READ,
	QUIC_STREAM_STATE_RECV_RESET_SEND,
	QUIC_STREAM_STATE_RECV_RESET_RECVD,
	QUIC_STREAM_STATE_RECV_RESET_READ,
} QuicStreamState;

/* Read-Write state */
typedef enum {
	QUIC_NOTHING = 0,
	QUIC_READING,
	QUIC_WRITING,
    QUIC_ASYNC_PAUSED,
} QuicReadWriteState;

typedef struct {
    QuicStreamState state;
    int (*read)(QUIC *);
    int (*write)(QUIC *);
} QuicStateMachine;

int QuicStateMachineAct(QUIC *, QuicStateMachine *, size_t);
int QuicConnect(QUIC *);
int QuicAccept(QUIC *);
int QuicStreamRead(QUIC *, RPacket *);

#endif
