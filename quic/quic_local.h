#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <tbquic/quic.h>

#include "statem.h"
#include "stream.h"
#include "cipher.h"
#include "buffer.h"
#include "tls.h"

#define QUIC_VERSION_1      0x01

#define QUIC_BUFFER_HEAD(buffer) (uint8_t *)((buffer)->buf->data)
#define QUIC_R_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->rbuffer)
#define QUIC_P_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->plain_buffer)
#define QUIC_W_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->wbuffer)

#define QUIC_BUFFER_DATA_LEN(buffer) (buffer)->data_len
#define QUIC_R_BUFFER_DATA_LEN(quic) QUIC_BUFFER_DATA_LEN(&quic->rbuffer)
#define QUIC_P_BUFFER_DATA_LEN(quic) QUIC_BUFFER_DATA_LEN(&quic->plain_buffer)
#define QUIC_W_BUFFER_DATA_LEN(quic) QUIC_BUFFER_DATA_LEN(&quic->wbuffer)

#define QUIC_FRAME_BUFFER(quic) (&quic->plain_buffer)

#define QUIC_IS_SERVER(q) (q->quic_server)
#define QUIC_IS_READING(q) QUIC_STATEM_READING(q->rwstate)
#define QUIC_IS_WRITNG(q) QUIC_STATEM_WRITNG(q->rwstate)

struct QuicMethod {
    uint32_t version;
    int (*quic_handshake)(QUIC *);
    int (*tls_init)(QUIC_TLS *);
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
    uint64_t pkt_acked;
} QuicCipherSpace;

typedef struct {
    QuicCipherSpace decrypt;
    QuicCipherSpace encrypt;
    bool cipher_initialed;
} QuicCrypto;

struct Quic {
    QUIC_TLS tls;
    QuicStreamState stream_state;
    QuicStatem statem;
    QuicReadWriteState rwstate;
#define quic_server tls.server
    uint32_t version;
    uint32_t mtu;
    uint64_t pkt_num_len:2;
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
    QUIC_DATA dcid;
    QUIC_DATA scid;
    QUIC_DATA token;
    QuicCrypto initial;
    struct {
        QUIC_CIPHERS ciphers;
    } zero_rtt;
    struct {
        QuicCipherSpace client;
        QuicCipherSpace server;
    } handshake;
};


#endif
