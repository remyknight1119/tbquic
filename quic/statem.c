/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include <assert.h>
#include <openssl/err.h>

#include "quic_local.h"
#include "log.h"

#define QUIC_TLS_ERR_STR_BUF_LEN    512

int QuicStateMachineAct(QUIC *quic, QuicStateMachine *statem, size_t num)
{
    QuicStateMachine *st = NULL;
    int ret = 0;

    assert(quic->statem >= 0 && quic->statem < num);
    st = &statem[quic->statem];

    if (st->read != NULL) {
        ret = st->read(quic);
        if (ret < 0) {
            return ret;
        }
    }

    if (st->write != NULL) {
        return st->write(quic);
    }

    return -1;
}


