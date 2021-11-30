#ifndef TBQUIC_QUIC_TLS_TLS_H_
#define TBQUIC_QUIC_TLS_TLS_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <tbquic/types.h>
#include "packet_local.h"
#include "buffer.h"
#include "statem.h"
#include "list.h"

#define TLS_RANDOM_BYTE_LEN     32
#define TLS_HANDSHAKE_LEN_SIZE  3
#define TLS_CIPHESUITE_LEN_SIZE sizeof(uint16_t)

#define TLS_MESSAGE_MAX_LEN     16384
#define TLS_VERSION_1_2         0x0303
#define TLS_VERSION_1_3         0x0304

#define TLS_IS_READING(t) QUIC_STATEM_READING(t->rwstate)
#define TLS_IS_WRITING(t) QUIC_STATEM_WRITING(t->rwstate)

typedef struct QuicTls QUIC_TLS;

typedef enum {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    HELLO_VERIFY_REQUEST = 3,
    NEW_SESSION_TICKET = 4,
    END_OF_EARLY_DATA = 5,
    HELLO_RETRY_REQUEST = 6,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20,
    CERTIFICATE_URL = 21,
    CERTIFICATE_STATUS = 22,
    SUPPLEMENTAL_DATA = 23,
    KEY_UPDATE = 24,
    MESSAGE_HASH = 254,
    HANDSHAKE_MAX,
} HandshakeType;

typedef enum {
    QUIC_TLS_ST_OK,
    QUIC_TLS_ST_CW_CLIENT_HELLO,
    QUIC_TLS_ST_CW_CLIENT_KEY_EXCHANGE,
    QUIC_TLS_ST_CR_SERVER_HELLO,
    QUIC_TLS_ST_SR_CLIENT_HELLO,
    QUIC_TLS_ST_SW_SERVER_HELLO,
    QUIC_TLS_ST_SW_SERVER_CERTIFICATE,
    QUIC_TLS_ST_MAX,
} QuicTlsState;

typedef struct {
    uint64_t max_idle_timeout;
} QuicTransportParams;

struct QuicTls {
    QuicTlsState handshake_state;
    QuicReadWriteState rwstate;
    uint8_t server:1;
    int (*handshake)(QUIC_TLS *, const uint8_t *, size_t);
    uint8_t client_random[TLS_RANDOM_BYTE_LEN];
    uint8_t server_random[TLS_RANDOM_BYTE_LEN];
    struct hlist_head cipher_list;
    QUIC_BUFFER buffer;
    QuicTransportParams trans_param;
};

typedef struct {
    QuicReadWriteState rwstate;
    QuicTlsState next_state;
    HandshakeType handshake_type;
    int (*handler)(QUIC_TLS *, void *);
} QuicTlsProcess;

#ifdef QUIC_TEST
extern uint8_t *quic_random_test;
#endif

int QuicTlsInit(QUIC_TLS *);
void QuicTlsFree(QUIC_TLS *);
int QuicTlsClientInit(QUIC_TLS *);
int QuicTlsServerInit(QUIC_TLS *);
int QuicTlsDoHandshake(QUIC_TLS *, const uint8_t *, size_t);
int QuicTlsDoProcess(QUIC_TLS *, RPacket *, WPacket *, const QuicTlsProcess *,
                        size_t);
int QuicTlsHandshake(QUIC_TLS *, const uint8_t *, size_t,
                        const QuicTlsProcess *, size_t);
int QuicTlsGenRandom(uint8_t *, size_t, WPacket *);
int QuicTlsPutCipherList(QUIC_TLS *, WPacket *);
int QuicTlsPutCompressionMethod(WPacket *);
int QuicTlsPutExtension(QUIC_TLS *, WPacket *);

#endif
