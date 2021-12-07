#ifndef TBQUIC_QUIC_STATEM_H_
#define TBQUIC_QUIC_STATEM_H_

#include <stddef.h>
#include <tbquic/types.h>

#define QUIC_STATEM_NOTHING(s) (s == QUIC_FLOW_NOTHING)
#define QUIC_STATEM_READING(s) (s == QUIC_FLOW_READING)
#define QUIC_STATEM_WRITING(s) (s == QUIC_FLOW_WRITING)
#define QUIC_STATEM_FINISHED(s) (s == QUIC_FLOW_FINISHED)

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
	QUIC_FINISHED,
} QuicReadWriteState;

/* Read-Write state */
typedef enum {
	QUIC_FLOW_NOTHING = 0,
	QUIC_FLOW_READING,
	QUIC_FLOW_WRITING,
	QUIC_FLOW_FINISHED,
} QuicFlowState;

typedef struct {
    int (*read)(QUIC *);
    int (*write)(QUIC *);
} QuicStateMachine;

int QuicStateMachineAct(QUIC *, QuicStateMachine *, size_t);
int QuicConnect(QUIC *);
int QuicAccept(QUIC *);
int QuicStreamRead(QUIC *);

#endif
