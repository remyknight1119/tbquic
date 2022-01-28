/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "transport.h"

#include <stddef.h>
#include <tbquic/quic.h>
#include "common.h"

static const QuicTransParamsDefines trans_param_offset[] = {
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, max_idle_timeout),
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, max_udp_payload_size),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, initial_max_data),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, initial_max_stream_data_bidi_local),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset =
            offsetof(QuicTransParams, initial_max_stream_data_bidi_remote),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, initial_max_stream_data_uni),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, initial_max_stream_bidi),
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, initial_max_stream_uni),
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
        .flags = QUIC_TRANS_PARAM_FLAGS_INT,
        .offset = offsetof(QuicTransParams, max_datagrame_frame_size),
    },
};

int QuicTransParamGetOffset(uint64_t type, size_t *offset)
{
    const QuicTransParamsDefines *p = NULL;
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
    size_t offset = 0;

    if (QuicTransParamGetOffset(type, &offset) < 0) {
        return -1;
    }

    QUIC_SET_U64_VALUE_BY_OFFSET(param, offset, value);

    return 0;
}

static int QuicTransParamGetU64(QuicTransParams *param, uint64_t type,
                                uint64_t *value)
{
    size_t offset = 0;

    if (QuicTransParamGetOffset(type, &offset) < 0) {
        return -1;
    }

    *value = QUIC_GET_U64_VALUE_BY_OFFSET(param, offset);

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

int QuicTransParamGet(QuicTransParams *param, uint64_t type, void *value,
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
            ret = QuicTransParamGetU64(param, type, value);
            break;
        default:
            return -1;
    };

    return ret;
}

int QuicTransParamNego(QuicTransParams *dest, QuicTransParams *client,
                        QuicTransParams *server)
{
    const QuicTransParamsDefines *p = NULL;
    size_t i = 0;
    uint64_t m_value;
    uint64_t c_value;
    uint64_t s_value;

    for (i = 0; i < QUIC_NELEM(trans_param_offset); i++) {
        p = &trans_param_offset[i];
        if (p->flags & QUIC_TRANS_PARAM_FLAGS_INT) {
            c_value = QUIC_GET_U64_VALUE_BY_OFFSET(client, p->offset);
            s_value = QUIC_GET_U64_VALUE_BY_OFFSET(server, p->offset);
            m_value = QUIC_MIN(c_value, s_value);
            QUIC_SET_U64_VALUE_BY_OFFSET(dest, p->offset, m_value);
            continue;
        }
    }

    return 0;
}

