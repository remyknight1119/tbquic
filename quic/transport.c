/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "transport.h"

#include <stddef.h>
#include <tbquic/quic.h>
#include "common.h"

static const QuicTransParamsOffset trans_param_offset[] = {
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
        .offset = offsetof(QuicTransParams, max_idle_timeout),
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
        .offset = offsetof(QuicTransParams, max_udp_payload_size),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
        .offset = offsetof(QuicTransParams, initial_max_data),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        .offset = offsetof(QuicTransParams, initial_max_stream_data_bidi_local),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .offset =
            offsetof(QuicTransParams, initial_max_stream_data_bidi_remote),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .offset = offsetof(QuicTransParams, initial_max_stream_data_uni),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
        .offset = offsetof(QuicTransParams, initial_max_stream_bidi),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
        .offset = offsetof(QuicTransParams, initial_max_stream_uni),
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
        .offset = offsetof(QuicTransParams, max_datagrame_frame_size),
    },
};

int QuicTransParamGetOffset(uint64_t type, size_t *offset)
{
    const QuicTransParamsOffset *p = NULL;
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(trans_param_offset); i++) {
        p = &trans_param_offset[i];
        if (p->type != type) {
            continue;
        }

        *offset = p->offset;
        return 0;
    }

    return -1;
}

static int QuicTransParamSetU64(QuicTransParams *param, uint64_t type,
                                uint64_t value)
{
    uint64_t *v = NULL;
    size_t offset = 0;

    if (QuicTransParamGetOffset(type, &offset) < 0) {
        return -1;
    }

    v = (uint64_t *)((uint8_t *)param + offset);
    *v = value;

    return 0;
}

int QuicTransParamSet(QuicTransParams *param, uint64_t type, void *value,
                                        size_t len)
{
    int ret = -1;

    switch (type) {
        case QUIC_TRANS_PARAM_ORIGINAL_DESTINATION_CONNECTION_ID:
        case QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT:
        case QUIC_TRANS_PARAM_STATELESS_RESET_TOKEN:
        case QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE:
        case QUIC_TRANS_PARAM_INITIAL_MAX_DATA:
        case QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
        case QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
        case QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI:
        case QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI:
        case QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI:
        case QUIC_TRANS_PARAM_ACK_DELAY_EXPONENT:
        case QUIC_TRANS_PARAM_MAX_ACK_DELAY:
        case QUIC_TRANS_PARAM_DISABLE_ACTIVE_MIGRATION:
        case QUIC_TRANS_PARAM_PREFERRED_ADDRESS:
        case QUIC_TRANS_PARAM_ACTIVE_CONNECTION_ID_LIMIT:
        case QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID:
        case QUIC_TRANS_PARAM_RETRY_SOURCE_CONNECTION_ID:
        case QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE:
            ret = QuicTransParamSetU64(param, type, *((uint64_t *)value));
            break;
        default:
            return -1;
    };

    return ret;
}

