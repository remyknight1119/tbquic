#ifndef TBQUIC_QUIC_STREAM_H_
#define TBQUIC_QUIC_STREAM_H_

#include <stdint.h>

#include <tbquic/types.h>
#include "base.h"
#include "list.h"

#define QUIC_STREAM_INITIATED_BY_SERVER     0x01
#define QUIC_STREAM_UNIDIRECTIONAL          0x02
#define QUIC_STREAM_ID_MASK                 0x03
#define QUIC_STREAM_ID_MASK_BITS            2

#define QUIC_STREAM_IS_UNI(id) (id & QUIC_STREAM_UNIDIRECTIONAL)

enum {
	QUIC_STREAM_STATE_DISABLE = 0,
	QUIC_STREAM_STATE_START,
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

enum {
    QUIC_STREAM_MSG_TYPE_DATA_RECVED = 0,
    QUIC_STREAM_MSG_TYPE_MAX,
};

typedef struct {
    uint64_t recv_state:4;
    uint64_t send_state:4;
    uint64_t notified:1;
    uint64_t local_opened:1;
    uint64_t uni:1;
    uint64_t max_stream_data;
    QuicDataStat stat_bytes;
    int64_t offset;
    struct list_head queue;
} QuicStreamInstance;

typedef struct {
    QuicDataStat stat_all;
    uint64_t bidi_id_alloced;
    uint64_t uni_id_alloced;
    uint64_t max_id_opened;
    uint64_t max_id_value;
    QuicStreamInstance *stream;
    struct list_head msg_queue;
} QuicStreamConf;

typedef struct {
    struct list_head node;
    uint32_t type;
    int64_t id;
} QuicStreamMsg;

typedef struct {
    struct list_head node;
    int64_t offset;
    const void *data;
    size_t len;
    void *origin_buf;
} QuicStreamData;

int QuicStreamInit(QUIC *);
void QuicStreamConfDeInit(QuicStreamConf *);
QuicStreamInstance *QuicStreamGetInstance(QUIC *, QUIC_STREAM_HANDLE);
QuicStreamData *QuicStreamDataCreate(void *, int64_t, const void *, size_t);
void QuicStreamDataAdd(QUIC *, QuicStreamData *, QuicStreamInstance *);
void QuicStreamDataFree(QuicStreamData *);
QuicStreamMsg *QuicStreamMsgCreate(int64_t, uint32_t);
void QuicStreamMsgAdd(QuicStreamConf *, QuicStreamMsg *);
void QuicStreamMsgFree(QuicStreamMsg *);
void QuicStreamDataCount(QuicStreamConf *, uint64_t, bool, bool);
int QuicStreamSendFlowCtrl(QUIC *, int64_t, size_t, uint32_t);

#endif
