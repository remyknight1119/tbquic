#ifndef TBQUIC_QUIC_STATEM_H_
#define TBQUIC_QUIC_STATEM_H_

#include <stddef.h>
#include <tbquic/types.h>

typedef enum {
	QUIC_STATEM_READY = 0,
	QUIC_STATEM_INITIAL_SENT,
	QUIC_STATEM_INITIAL_RECV,
	QUIC_STATEM_HANDSHAKE_RECV,
	QUIC_STATEM_HANDSHAKE_DONE,
	QUIC_STATEM_MAX,
} QuicStatem;

/* Read-Write state */
typedef enum {
	QUIC_NOTHING = 0,
	QUIC_READING,
	QUIC_WRITING,
    QUIC_ASYNC_PAUSED,
} QuicReadWriteState;

typedef struct {
    int (*read)(QUIC *);
    int (*write)(QUIC *);
} QuicStateMachine;

int QuicStateMachineAct(QUIC *, QuicStateMachine *, size_t);
int QuicConnect(QUIC *);
int QuicAccept(QUIC *);
int QuicStreamRead(QUIC *);

#endif
