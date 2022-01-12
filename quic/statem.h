#ifndef TBQUIC_QUIC_STATEM_H_
#define TBQUIC_QUIC_STATEM_H_

#include <stddef.h>
#include <tbquic/types.h>

#include "base.h"
#include "packet_local.h"
#include "format.h"

#define QUIC_FLOW_STATEM_NOTHING(s) (s == QUIC_FLOW_NOTHING)
#define QUIC_FLOW_STATEM_READING(s) (s == QUIC_FLOW_READING)
#define QUIC_FLOW_STATEM_WRITING(s) (s == QUIC_FLOW_WRITING)
#define QUIC_FLOW_STATEM_FINISHED(s) (s == QUIC_FLOW_FINISHED)

typedef enum {
    QUIC_FLOW_RET_ERROR,
    QUIC_FLOW_RET_WANT_READ,
    QUIC_FLOW_RET_WANT_WRITE,
    QUIC_FLOW_RET_CONTINUE,
    QUIC_FLOW_RET_FINISH,
    QUIC_FLOW_RET_END,
} QuicFlowReturn;

typedef QuicFlowReturn (*QuicStatemRead)(QUIC *, RPacket *, QuicPacketFlags);
typedef QuicFlowReturn (*QuicStatemWrite)(QUIC *);

typedef enum {
	QUIC_STATEM_INITIAL = 0,
	QUIC_STATEM_HANDSHAKE,
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
    QuicStatemRead recv;
    QuicStatemWrite send;
} QuicStatemFlow;

QuicFlowReturn QuicInitialRecv(QUIC *, RPacket *, QuicPacketFlags);
QuicFlowReturn QuicInitialSend(QUIC *);
QuicFlowReturn QuicHandshakeRecv(QUIC *, RPacket *, QuicPacketFlags);
int QuicStateMachineAct(QUIC *, const QuicStatemFlow *, size_t);
int QuicConnect(QUIC *);
int QuicAccept(QUIC *);
int QuicStreamRead(QUIC *);
int QuicStateMachine(QUIC *);
int QuicCidGen(QUIC_DATA *, size_t);

#endif
