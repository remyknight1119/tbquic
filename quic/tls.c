/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "tls.h"

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
    uint32_t type = 0;


    while (RPacketGet1(pkt, &type) >= 0) {
        if (type != tls->next_type) {
            QUIC_LOG("type not match\n");
            return -1;
        }

        if (type >= num) {
            QUIC_LOG("type invalid\n");
            return -1;
        }

        p = &proc[type];
        if (p->proc == NULL) {
            QUIC_LOG("No proc found\n");
            return -1;
        }

        if (p->proc(tls, pkt) < 0) {
            QUIC_LOG("Proc failed\n");
            return -1;
        }

        /* If proc not assign next_type, use default */
        if (type == tls->next_type) {
            tls->next_type = p->next_type;
        }
    }

    return 0;
}

int QuicTlsInit(QUIC_TLS *tls, const QUIC_METHOD *method)
{
    tls->handshake = method->tls_handshake;
    tls->next_type = tls->server ? CLIENT_HELLO : SERVER_HELLO;

    return 0;
}
