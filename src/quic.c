
#include <tbquic/tbquic.h>

#include "stream.h"
#include "mem.h"
#include "quic.h"

QUIC *QuicNew(void)
{
    QUIC *quic = NULL;

    quic = QuicMemCalloc(sizeof(*quic));
    if (quic == NULL) {
        return NULL;
    }

    quic->state = TBQUIC_STREAM_STATE_READY;

    return quic;
}

void QuicFree(QUIC *quic)
{
    QuicMemFree(quic);
}
