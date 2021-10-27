/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "statem.h"

#include "quic_local.h"

int QuicStateMachineAct(QUIC *quic, QuicStateMachine *statem, size_t num)
{
    int     i = 0;
    int     ret = 0;

    for (i = 0; i < num; i++) {
        if (quic->state != statem[i].state) {
            continue;
        }

        if (statem[i].read != NULL) {
            ret = statem[i].read(quic);
            if (ret < 0) {
                return ret;
            }
        }
        if (statem[i].write != NULL) {
            return statem[i].write(quic);
        }
    }

    return -1;
}
