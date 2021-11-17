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

int QuicTlsDoProcess(QUIC_TLS *tls, RPacket *pkt, const QuicTlsProcess *proc,
                        size_t num)
{
    const QuicTlsProcess *p = NULL;
    QuicTlsState state = 0;
    uint32_t type = 0;

    while (RPacketGet1(pkt, &type) >= 0) {
        state = tls->state;

        assert(state >= QUIC_TLS_ST_OK && state < QUIC_TLS_ST_MAX);

        p = &proc[state];
        if (p->proc == NULL) {
            QUIC_LOG("No proc found\n");
            return -1;
        }

        if (type != p->expect) {
            QUIC_LOG("type not match\n");
            return -1;
        }

        if (type >= num) {
            QUIC_LOG("type invalid\n");
            return -1;
        }

        if (p->proc(tls, pkt) < 0) {
            QUIC_LOG("Proc failed\n");
            return -1;
        }

        /* If proc not assign next_state, use default */
        if (state == tls->state) {
            tls->state = p->next_state;
        }
    }

    return 0;
}


