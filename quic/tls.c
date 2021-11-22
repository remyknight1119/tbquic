/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

#include <assert.h>
#include <tbquic/types.h>
#include <tbquic/quic.h>

#include "packet_local.h"
#include "quic_local.h"
#include "log.h"

int QuicTlsDoHandshake(QUIC_TLS *tls, const uint8_t *data, size_t len)
{
    return tls->handshake(tls, data, len);
}

int QuicTlsDoProcess(QUIC_TLS *tls, RPacket *rpkt, WPacket *wpkt,
                        const QuicTlsProcess *proc, size_t num)
{
    const QuicTlsProcess *p = NULL;
    QuicTlsState state = 0;
    uint32_t type = 0;

    state = tls->handshake_state;
    assert(state >= 0 && state < num);
    p = &proc[state];

    while (QUIC_STATEM_READING(p->rwstate)) {
        tls->rwstate = p->rwstate;
        if (RPacketGet1(rpkt, &type) < 0) {
            return -1;
        }

        if (p->read == NULL) {
            QUIC_LOG("No read func found\n");
            return -1;
        }

        if (type != p->expect) {
            QUIC_LOG("type not match\n");
            return -1;
        }

        state = tls->handshake_state;
        if (p->read(tls, rpkt) < 0) {
            QUIC_LOG("Proc failed\n");
            return -1;
        }

        /* If proc not assign next_state, use default */
        if (state == tls->handshake_state) {
            tls->handshake_state = p->next_state;
        }

        state = tls->handshake_state;
        assert(state >= 0 && state < num);
        p = &proc[state];
    }

    while (QUIC_STATEM_WRITING(p->rwstate)) {
        tls->rwstate = p->rwstate;
        if (p->write == NULL) {
            QUIC_LOG("No write func found\n");
            return -1;
        }

        state = tls->handshake_state;
        if (p->write(tls, wpkt) < 0) {
            QUIC_LOG("Proc failed\n");
            return -1;
        }

        /* If proc not assign next_state, use default */
        if (state == tls->handshake_state) {
            tls->handshake_state = p->next_state;
        }

        state = tls->handshake_state;
        assert(state >= 0 && state < num);
        p = &proc[state];
    }

    return 0;
}

int QuicTlsBuildMessage(QUIC_TLS *tls, WPacket *pkt, const QuicTlsBuild *b,
                        size_t b_num)
{
    return 0;
}

int QuicTlsInit(QUIC_TLS *tls)
{
    if (QuicBufInit(&tls->buffer, TLS_MESSAGE_MAX_LEN) < 0) {
        return -1;
    }

    return 0;
}

void QuicTlsFree(QUIC_TLS *tls)
{
    QuicBufFree(&tls->buffer);
}

