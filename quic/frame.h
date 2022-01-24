#ifndef TBQUIC_QUIC_FRAME_H_
#define TBQUIC_QUIC_FRAME_H_

#include <tbquic/types.h>

#include "base.h"
#include "packet_local.h"
    
#define QUIC_FRAME_STREAM_BIT_FIN       0x01
#define QUIC_FRAME_STREAM_BIT_LEN       0x02
#define QUIC_FRAME_STREAM_BIT_OFF       0x04

/* type + offset + length */
#define QUIC_FRAME_HEADER_MAX_LEN   (3*sizeof(uint32_t))

typedef int (*QuicFrameParser)(QUIC *, RPacket *, uint64_t, QUIC_CRYPTO *);
typedef int (*QuicFrameBuilder)(QUIC *, WPacket *, QUIC_CRYPTO *, uint64_t,
                                    void *, long);

typedef enum {
    QUIC_FRAME_TYPE_PADDING = 0x00,
    QUIC_FRAME_TYPE_PING = 0x01,
    QUIC_FRAME_TYPE_ACK = 0x02,
    QUIC_FRAME_TYPE_ACK_ECN_COUNTS = 0x03,
    QUIC_FRAME_TYPE_RESET_STREAM = 0x04,
    QUIC_FRAME_TYPE_STOP_SENDING = 0x05,
    QUIC_FRAME_TYPE_CRYPTO = 0x06,
    QUIC_FRAME_TYPE_NEW_TOKEN = 0x07,
    QUIC_FRAME_TYPE_STREAM = 0x08,
    QUIC_FRAME_TYPE_STREAM_FIN = 0x09,
    QUIC_FRAME_TYPE_STREAM_LEN = 0x0a,
    QUIC_FRAME_TYPE_STREAM_LEN_FIN = 0x0b,
    QUIC_FRAME_TYPE_STREAM_OFF = 0x0c,
    QUIC_FRAME_TYPE_STREAM_OFF_FIN = 0x0d,
    QUIC_FRAME_TYPE_STREAM_OFF_LEN = 0x0e,
    QUIC_FRAME_TYPE_STREAM_OFF_LEN_FIN = 0x0f,
    QUIC_FRAME_TYPE_MAX_DATA = 0x10,
    QUIC_FRAME_TYPE_MAX_STREAM_DATA = 0x11,
    QUIC_FRAME_TYPE_MAX_STREAMS = 0x12,
    QUIC_FRAME_TYPE_DATA_BLOCKED = 0x14,
    QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED = 0x15,
    QUIC_FRAME_TYPE_STREAMS_BLOCKED = 0x16,
    QUIC_FRAME_TYPE_NEW_CONNECTION_ID = 0x18,
    QUIC_FRAME_TYPE_RETIRE_CONNECTION_ID = 0x19,
    QUIC_FRAME_TYPE_PATH_CHALLENGE = 0x1a,
    QUIC_FRAME_TYPE_PATH_RESPONSE = 0x1b,
    QUIC_FRAME_TYPE_CONNECTION_CLOSE = 0x1c,
    QUIC_FRAME_TYPE_HANDSHAKE_DONE = 0x1e,
    QUIC_FRAME_TYPE_MAX,
} QuicFrameType;

typedef struct {
#define QUIC_FRAME_FLAGS_NO_BODY        0x0001
#define QUIC_FRAME_FLAGS_SPLIT_ENABLE   0x0002
#define QUIC_FRAME_FLAGS_SKIP           0x0004
    uint64_t flags;
    QuicFrameParser parser;
    QuicFrameBuilder builder;
} QuicFrameProcess;

typedef struct {
    void *data;
    size_t len;
} QuicFrameCryptoArg;

typedef struct {
    uint64_t id;
    void *data;
    size_t len;
} QuicFrameStreamArg;

typedef struct {
    uint64_t type;
    void *arg;
    long larg;
} QuicFrameNode;

int QuicFrameDoParser(QUIC *, RPacket *, QUIC_CRYPTO *, uint32_t);
int QuicFramePaddingBuild(WPacket *, size_t);
int QuicFramePingBuild(QUIC *, WPacket *, uint8_t *, uint64_t, size_t);
int QuicFrameBuild(QUIC *, uint32_t, QuicFrameNode *, size_t);
int QuicFrameAckSendCheck(QUIC_CRYPTO *c);
int QuicCryptoFrameBuild(QUIC *, uint32_t);
int QuicStreamFrameBuild(QUIC * ,QUIC_STREAM_HANDLE, uint8_t *, size_t);
int QuicAckFrameBuild(QUIC *, uint32_t);

#endif
