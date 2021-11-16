#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>

#include <openssl/bio.h>
#include <tbquic/quic.h>

#include "statem.h"
#include "cipher.h"
#include "buffer.h"
#include "tls.h"

#define QUIC_VERSION_1      0x01

#define QUIC_BUFFER_HEAD(buffer) buffer.buf->data
#define QUIC_R_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->rbuffer)
#define QUIC_P_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->plain_buffer)
#define QUIC_W_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(quic->wbuffer)

#define QUIC_IS_SERVER(q) (q->quic_server)

struct QuicMethod {
    int (*quic_handshake)(QUIC *);
    int (*tls_handshake)(QUIC_TLS *, const uint8_t *, size_t);
    uint8_t server:1;
};

struct QuicCtx {
    const QUIC_METHOD *method;
    uint32_t mtu;
};

typedef struct {
    uint8_t *data;
    size_t len;
} QUIC_DATA;

typedef struct {
    QUIC_CIPHERS ciphers;
    uint64_t pkt_num;
} QuicCipherSpace;

struct Quic {
    QUIC_TLS tls;
    QuicStreamState state;
    QuicReadWriteState rwstate;
#define quic_server tls.server
    uint32_t mtu;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    BIO *rbio;
    BIO *wbio;
    int (*do_handshake)(QUIC *);
    /* Read Buffer */
    QUIC_BUFFER rbuffer;
    QUIC_BUFFER plain_buffer;
    /* Write Buffer */
    QUIC_BUFFER wbuffer;
    QUIC_DATA cid;
    struct {
        QuicCipherSpace client;
        QuicCipherSpace server;
    } initial;
    struct {
        QUIC_CIPHERS ciphers;
    } zero_rtt;
    struct {
        QuicCipherSpace client;
        QuicCipherSpace server;
    } handshake;
};


#endif
