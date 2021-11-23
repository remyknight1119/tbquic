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

static int QuicTlsStatem(QUIC_TLS *tls, const QuicTlsProcess *p, void *pkt)
{
    QuicTlsState state = 0;

    state = tls->handshake_state;
    if (p->handler(tls, pkt) < 0) {
        QUIC_LOG("Proc failed\n");
        return -1;
    }

    tls->rwstate = QUIC_FINISHED;
    /* If proc not assign next_state, use default */
    if (state == tls->handshake_state) {
        tls->handshake_state = p->next_state;
    }

    return 0;
}

static int QuicReadProcess(QUIC_TLS *tls, const QuicTlsProcess *p,
                            RPacket *pkt)
{
    uint32_t type = 0;

    tls->rwstate = p->rwstate;
    if (p->handler == NULL) {
        QUIC_LOG("No handler func found\n");
        return -1;
    }

    if (RPacketGet1(pkt, &type) < 0) {
        return -1;
    }

    if (type != p->expect) {
        QUIC_LOG("type not match\n");
        return -1;
    }

    return QuicTlsStatem(tls, p, pkt);
}

static int QuicWriteProcess(QUIC_TLS *tls, const QuicTlsProcess *p,
                            WPacket *pkt)
{
    tls->rwstate = p->rwstate;
    if (p->handler == NULL) {
        QUIC_LOG("No handler func found\n");
        return -1;
    }

    return QuicTlsStatem(tls, p, pkt);
}

int QuicTlsDoProcess(QUIC_TLS *tls, RPacket *rpkt, WPacket *wpkt,
                        const QuicTlsProcess *proc, size_t num)
{
    const QuicTlsProcess *p = NULL;
    QuicTlsState state = 0;

    state = tls->handshake_state;
    assert(state >= 0 && state < num);
    p = &proc[state];

    while (!QUIC_STATEM_FINISHED(p->rwstate)) {
        switch (p->rwstate) {
            case QUIC_NOTHING:
                tls->handshake_state = p->next_state;
                break;
            case QUIC_READING:
                if (p->handler == NULL) {
                    QUIC_LOG("No handler func found\n");
                    return 0;
                }
                if (QuicReadProcess(tls, p, rpkt) < 0) {
                    return -1;
                }
                break;
            case QUIC_WRITING:
                if (p->handler == NULL) {
                    QUIC_LOG("No handler func found\n");
                    return 0;
                }
                if (QuicWriteProcess(tls, p, wpkt) < 0) {
                    return -1;
                }

                break;
            default:
                QUIC_LOG("Unknown rw state(%d)\n", p->rwstate);
                return -1;
        }
        state = tls->handshake_state;
        assert(state >= 0 && state < num);
        p = &proc[state];
    }

    return 0;
}

int QuicTlsHandshake(QUIC_TLS *tls, const uint8_t *data, size_t len,
                        const QuicTlsProcess *proc, size_t num)
{
    QUIC_BUFFER *buffer = &tls->buffer;
    RPacket rpkt = {};
    WPacket wpkt = {};
    int ret = 0;

    RPacketBufInit(&rpkt, data, len);
    WPacketBufInit(&wpkt, buffer->buf);

    ret = QuicTlsDoProcess(tls, &rpkt, &wpkt, proc, num);
    buffer->data_len = WPacket_get_written(&wpkt);

    return ret;
}

int QuicTlsInit(QUIC_TLS *tls)
{
    tls->handshake_state = QUIC_TLS_ST_OK;
    if (QuicBufInit(&tls->buffer, TLS_MESSAGE_MAX_LEN) < 0) {
        return -1;
    }

    return 0;
}

void QuicTlsFree(QUIC_TLS *tls)
{
    QuicBufFree(&tls->buffer);
}

