#ifndef TBQUIC_QUIC_TRANSPORT_H_
#define TBQUIC_QUIC_TRANSPORT_H_

#include <stdint.h>
#include <stddef.h>

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
} QuicTransParams;

typedef struct {
    uint64_t type;
    size_t offset;
} QuicTransParamsOffset;

int QuicTransParamGetOffset(uint64_t, size_t *);
int QuicTransParamSet(QuicTransParams *, uint64_t, void *, size_t);

#endif
