#ifndef TBQUIC_QUIC_TLS_H_
#define TBQUIC_QUIC_TLS_H_

#include <stdint.h>
#include <stddef.h>

#include <tbquic/types.h>
#include "packet_local.h"
#include "buffer.h"

#define TLS_RANDOM_BYTE_LEN     32

#define TLS_MESSAGE_MAX_LEN     16384

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
    QUIC_TLS_ST_CLIENT_HELLO,
    QUIC_TLS_ST_SERVER_HELLO,
    QUIC_TLS_ST_CLIENT_KEY_EXCHANGE,
    QUIC_TLS_ST_MAX,
} QuicTlsState;

struct QuicTls {
    QuicTlsState state;
    uint8_t server:1;
    int (*handshake)(QUIC_TLS *, const uint8_t *, size_t);
    uint8_t client_random[TLS_RANDOM_BYTE_LEN];
    uint8_t server_random[TLS_RANDOM_BYTE_LEN];
    QUIC_BUFFER buffer;
};

typedef struct {
    QuicTlsState next_state;
    HandshakeType expect;
    int (*proc)(QUIC_TLS *, RPacket *);
} QuicTlsProcess;

int QuicTlsInit(QUIC_TLS *);
void QuicTlsFree(QUIC_TLS *);
int QuicTlsClientInit(QUIC_TLS *);
int QuicTlsServerInit(QUIC_TLS *);
int QuicTlsDoHandshake(QUIC_TLS *, const uint8_t *, size_t);
int QuicTlsDoProcess(QUIC_TLS *, RPacket *, const QuicTlsProcess *, size_t);

#endif
