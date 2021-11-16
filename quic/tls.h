#ifndef TBQUIC_QUIC_TLS_H_
#define TBQUIC_QUIC_TLS_H_

#include <stdint.h>
#include <stddef.h>

#include <tbquic/types.h>
#include "packet_local.h"

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

struct QuicTls {
    HandshakeType next_type;
    uint8_t server:1;
    int (*handshake)(QUIC_TLS *, const uint8_t *, size_t);
};

typedef struct {
    HandshakeType next_type;
    int (*proc)(QUIC_TLS *, RPacket *);
} QuicTlsProcess;

int QuicTlsInit(QUIC_TLS *, const QUIC_METHOD *);
int QuicTlsDoHandshake(QUIC_TLS *, const uint8_t *, size_t);
int QuicTlsConnect(QUIC_TLS *, const uint8_t *, size_t);
int QuicTlsAccept(QUIC_TLS *, const uint8_t *, size_t);
int QuicTlsDoProcess(QUIC_TLS *, RPacket *, const QuicTlsProcess *, size_t);

#endif
