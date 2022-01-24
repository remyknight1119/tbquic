#ifndef TBQUIC_QUIC_TRANSPORT_H_
#define TBQUIC_QUIC_TRANSPORT_H_

#include <stdint.h>
#include <stddef.h>

#define QUIC_TRANS_PARAM_STATELESS_RESET_TOKEN_LEN   16

typedef struct {
    uint64_t max_idle_timeout;
    uint16_t max_udp_payload_size;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_data_bidi_local; 
    uint64_t initial_max_stream_data_bidi_remote; 
    uint64_t initial_max_stream_data_uni; 
    uint64_t initial_max_stream_bidi; 
    uint64_t initial_max_stream_uni; 
    uint64_t max_datagrame_frame_size; 
    uint8_t stateless_reset_token[QUIC_TRANS_PARAM_STATELESS_RESET_TOKEN_LEN];
} QuicTransParams;

typedef struct {
    uint64_t type;
#define QUIC_TRANS_PARAM_FLAGS_INT  0x0001
    uint64_t flags;
    size_t offset;
} QuicTransParamsDefines;

int QuicTransParamGetOffset(uint64_t, size_t *);
int QuicTransParamSet(QuicTransParams *, uint64_t, void *, size_t);
int QuicTransParamNego(QuicTransParams *, QuicTransParams *, QuicTransParams *);

#endif
