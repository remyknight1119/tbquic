#ifndef TBQUIC_QUIC_QUIC_LOCAL_H_
#define TBQUIC_QUIC_QUIC_LOCAL_H_

#include <stdint.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <tbquic/quic.h>

#include "base.h"
#include "statem.h"
#include "stream.h"
#include "cipher.h"
#include "buffer.h"
#include "tls.h"
#include "cert.h"

#define QUIC_VERSION_1      0x01

#define QUIC_BUFFER_HEAD(buffer) (uint8_t *)((buffer)->buf->data)
#define QUIC_R_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->rbuffer)
#define QUIC_P_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->plain_buffer)
#define QUIC_W_BUFFER_HEAD(quic) QUIC_BUFFER_HEAD(&quic->wbuffer)

#define QUIC_BUFFER_DATA_LEN(buffer) (buffer)->data_len
#define QUIC_R_BUFFER_DATA_LEN(quic) QUIC_BUFFER_DATA_LEN(&quic->rbuffer)
#define QUIC_P_BUFFER_DATA_LEN(quic) QUIC_BUFFER_DATA_LEN(&quic->plain_buffer)
#define QUIC_W_BUFFER_DATA_LEN(quic) QUIC_BUFFER_DATA_LEN(&quic->wbuffer)

#define QUIC_READ_BUFFER(quic) (&quic->rbuffer)
#define QUIC_WRITE_BUFFER(quic) (&quic->wbuffer)
#define QUIC_FRAME_BUFFER(quic) (&quic->plain_buffer)
#define QUIC_TLS_BUFFER(quic) (&quic->tls.buffer)

#define QUIC_IS_SERVER(q) (q->quic_server)
#define QUIC_IS_READING(q) QUIC_STATEM_READING(q->rwstate)
#define QUIC_IS_WRITNG(q) QUIC_STATEM_WRITNG(q->rwstate)

#define QUIC_GET_FLOW_STATE(q) ((q)->statem.flow_state)
#define QUIC_SET_FLOW_STATE(q, v) \
    do { \
        (q)->statem.flow_state = v; \
    } while (0)

struct QuicMethod {
    uint32_t version;
    int (*quic_connect)(QUIC *);
    int (*quic_accept)(QUIC *);
};

struct QuicCtx {
    const QUIC_METHOD *method;
    uint32_t mtu;
    QuicCert *cert;
    struct {
        QUIC_DATA alpn;
        QuicTransParams trans_param;
        QUIC_DATA supported_groups;
    } ext;
};

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

typedef struct {
    QuicStatem state;
    QuicReadState read_state;
    QuicReadWriteState rwstate;
    QuicFlowState flow_state; 
} QUIC_STATEM;

struct Quic {
    QUIC_TLS tls;
#define quic_server tls.server
    QuicStreamState stream_state;
    QUIC_STATEM statem;
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

static inline QUIC *QuicTlsTrans(QUIC_TLS *tls)
{
    return (QUIC *)tls;
}


#endif
