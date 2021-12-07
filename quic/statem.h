#ifndef TBQUIC_QUIC_STATEM_H_
#define TBQUIC_QUIC_STATEM_H_

#include <stddef.h>
#include <tbquic/types.h>

#define QUIC_FLOW_STATEM_NOTHING(s) (s == QUIC_FLOW_NOTHING)
#define QUIC_FLOW_STATEM_READING(s) (s == QUIC_FLOW_READING)
#define QUIC_FLOW_STATEM_WRITING(s) (s == QUIC_FLOW_WRITING)
#define QUIC_FLOW_STATEM_FINISHED(s) (s == QUIC_FLOW_FINISHED)

typedef enum {
    QUIC_FLOW_RET_ERROR,
    QUIC_FLOW_RET_WANT_READ,
    QUIC_FLOW_RET_FINISH,
} QuicFlowReturn;

typedef QuicFlowReturn (*QuicStatemHandler)(QUIC *, void *);

typedef enum {
	QUIC_STATEM_READY = 0,
	QUIC_STATEM_INITIAL_SEND,
	QUIC_STATEM_INITIAL_RECV,
	QUIC_STATEM_HANDSHAKE_RECV,
	QUIC_STATEM_HANDSHAKE_SEND,
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

/* Read state */
typedef enum {
	QUIC_WANT_DATA = 0,
	QUIC_DATA_READY,
} QuicReadState;

/* Flow state */
typedef enum {
	QUIC_FLOW_NOTHING = 0,
	QUIC_FLOW_READING,
	QUIC_FLOW_WRITING,
	QUIC_FLOW_FINISHED,
} QuicFlowState;

typedef struct {
    QuicFlowState flow_state;
    QuicStatem next_state;
    QuicStatemHandler handler;
} QuicStateMachine;

QuicFlowReturn QuicStateMachineAct(QUIC *, const QuicStateMachine *, size_t);
int QuicConnect(QUIC *);
int QuicAccept(QUIC *);
int QuicStreamRead(QUIC *);

#endif
