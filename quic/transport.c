/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "transport.h"

#include <stddef.h>
#include <tbquic/quic.h>
#include "common.h"

static void QuicTransParamActiveConnIdLimitInit(QuicTransParams *, uint64_t);
static int QuicTransParamGetInt(QuicTransParams *, uint64_t, void *, size_t);
static int QuicTransParamGetActiveConnIdLimit(QuicTransParams *, uint64_t,
                                void *, size_t);
static int QuicTransParamSetInt(QuicTransParams *, uint64_t, void *, size_t);
static const QuicTransParamsDefines trans_param_definition[] = {
    {
        .type = QUIC_TRANS_PARAM_MAX_IDLE_TIMEOUT,
        .offset = offsetof(QuicTransParams, max_idle_timeout),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_UDP_PAYLOAD_SIZE,
        .offset = offsetof(QuicTransParams, max_udp_payload_size),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_DATA,
        .offset = offsetof(QuicTransParams, initial_max_data),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        .offset = offsetof(QuicTransParams, initial_max_stream_data_bidi_local),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        .offset =
            offsetof(QuicTransParams, initial_max_stream_data_bidi_remote),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAM_DATA_UNI,
        .offset = offsetof(QuicTransParams, initial_max_stream_data_uni),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_BIDI,
        .offset = offsetof(QuicTransParams, initial_max_stream_bidi),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_MAX_STREAMS_UNI,
        .offset = offsetof(QuicTransParams, initial_max_stream_uni),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_ACTIVE_CONNECTION_ID_LIMIT,
        .offset = offsetof(QuicTransParams, active_connection_id_limit),
        .init = QuicTransParamActiveConnIdLimitInit,
        .get_value = QuicTransParamGetActiveConnIdLimit,
        .set_value = QuicTransParamSetInt,
    },
    {
        .type = QUIC_TRANS_PARAM_INITIAL_SOURCE_CONNECTION_ID,
    },
    {
        .type = QUIC_TRANS_PARAM_MAX_DATAGRAME_FRAME_SIZE,
        .offset = offsetof(QuicTransParams, max_datagrame_frame_size),
        .get_value = QuicTransParamGetInt,
        .set_value = QuicTransParamSetInt,
    },
};

static const QuicTransParamsDefines *QuicTransParamDefFind(uint64_t type)
{
    const QuicTransParamsDefines *p = NULL;
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(trans_param_definition); i++) {
        p = &trans_param_definition[i];
        if (p->type == type) {
            return p;
        }

    }

    return NULL;
}

int QuicTransParamGetOffset(uint64_t type, size_t *offset)
{
    const QuicTransParamsDefines *p = NULL;

    p = QuicTransParamDefFind(type);
    if (p == NULL) {
        return -1;
    }

    *offset = p->offset;

    return 0;
}

static int QuicTransParamGetInt(QuicTransParams *param, uint64_t offset,
                                    void *value, size_t len)
{
    *((uint64_t *)value) = QUIC_GET_U64_VALUE_BY_OFFSET(param, offset);

    return 0;
}

static int QuicTransParamGetActiveConnIdLimit(QuicTransParams *param,
                                    uint64_t offset, void *value,
                                    size_t len)
{
    QuicTransParamGetInt(param, offset, value, len);

    if (*((uint64_t *)value) < QUIC_TRANS_ACTIVE_CONN_ID_LIMIT) {
        *((uint64_t *)value) = QUIC_TRANS_ACTIVE_CONN_ID_LIMIT;
    }

    return 0;
}

static int QuicTransParamSetInt(QuicTransParams *param, uint64_t offset,
                                    void *value, size_t len)
{
    QUIC_SET_U64_VALUE_BY_OFFSET(param, offset, *((uint64_t *)value));

    return 0;
}

int QuicTransParamSet(QuicTransParams *param, uint64_t type, void *value,
                                        size_t len)
{
    const QuicTransParamsDefines *p = NULL;

    p = QuicTransParamDefFind(type);
    if (p == NULL) {
        return -1;
    }

    return p->set_value(param, p->offset, value, len);
}

int QuicTransParamGet(QuicTransParams *param, uint64_t type, void *value,
                                        size_t len)
{
    const QuicTransParamsDefines *p = NULL;

    p = QuicTransParamDefFind(type);
    if (p == NULL) {
        return -1;
    }

    return p->get_value(param, p->offset, value, len);
}

void QuicTransParamInit(QuicTransParams *param)
{
    const QuicTransParamsDefines *p = NULL;
    size_t i = 0;

    for (i = 0; i < QUIC_NELEM(trans_param_definition); i++) {
        p = &trans_param_definition[i];
        if (p->init != NULL) {
            p->init(param, p->offset);
        }
    }
}

static void QuicTransParamActiveConnIdLimitInit(QuicTransParams *param,
                                                    uint64_t offset)
{
    QUIC_SET_U64_VALUE_BY_OFFSET(param, offset,
                QUIC_TRANS_ACTIVE_CONN_ID_LIMIT);
}

