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
#include "list.h"
#include "q_buff.h"
#include "address.h"
#include "packet_local.h"

#define QUIC_VERSION_1      0x01

#define QUIC_STREAM_GET_RECV_STATE(q) (q)->stream_state.recv_state
#define QUIC_STREAM_GET_SEND_STATE(q) (q)->stream_state.send_state
#define QUIC_STREAM_SET_RECV_STATE(q, s) \
    do { \
        (q)->stream_state.recv_state = s; \
    } while (0)

#define QUIC_STREAM_SET_SEND_STATE(q, s) \
    do { \
        (q)->stream_state.send_state = s; \
    } while (0)

#define QUIC_BUFFER_HEAD(buffer) (uint8_t *)((buffer)->buf->data)

#define QUIC_READ_BUFFER(quic) (&quic->rbuffer)
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
    int (*read_bytes)(QUIC *, RPacket *);
    const TlsMethod *tls_method;
};

struct QuicCtx {
    const QUIC_METHOD *method;
    /* Max Segment Size */
    uint32_t mss;
    uint32_t verify_mode;
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
    bool cipher_inited;
} QuicCipherSpace;

struct QuicCrypto {
    QuicCipherSpace decrypt;
    QuicCipherSpace encrypt;
};

typedef struct {
    QuicStatem state;
    QuicReadState read_state;
    QuicReadWriteState rwstate;
    QuicFlowState flow_state; 
} QUIC_STATEM;

struct Quic {
    /* This member must be first */
    TLS tls;
#define quic_server tls.server
    QuicStreamState stream_state;
    QUIC_STATEM statem;
    struct list_head node; 
    uint32_t version;
    uint32_t mss;
    uint32_t verify_mode;
    uint64_t pkt_num_len:2;
    uint64_t cid_len:8;
    uint64_t fd_mode:1;
    const QUIC_CTX *ctx;
    const QUIC_METHOD *method;
    BIO *rbio;
    BIO *wbio;
    void *dispenser_buf;
    int (*do_handshake)(QUIC *);
    Address source;
    Address dest;
    /* Read Buffer */
    QUIC_BUFFER rbuffer;
    QUIC_DATA dcid;
    QUIC_DATA scid;
    QUIC_DATA token;
    QUIC_CRYPTO initial;
    QUIC_CRYPTO handshake;
    QUIC_CRYPTO zero_rtt;
    QUIC_CRYPTO one_rtt;
    QBUFF *send_head;
    QBuffQueueHead rx_queue;
    QBuffQueueHead tx_queue;
};

static inline QUIC *QuicTlsTrans(TLS *s)
{
    return (QUIC *)s;
}

int QUIC_set_handshake_hp_cipher(QUIC *, uint32_t);
int QUIC_set_pp_cipher_space_alg(QuicCipherSpace *, uint32_t);
int QUIC_set_hp_cipher(QUIC_CRYPTO *, uint32_t);
int QUIC_set_hp_cipher_space_alg(QuicCipherSpace *, uint32_t);
QUIC_CRYPTO *QuicGetInitialCrypto(QUIC *);
QUIC_CRYPTO *QuicGetHandshakeCrypto(QUIC *);
QUIC_CRYPTO *QuicGetOneRttCrypto(QUIC *);


#endif
