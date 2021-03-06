#ifndef TBQUIC_INCLUDE_TYPES_H_
#define TBQUIC_INCLUDE_TYPES_H_

#include <stdint.h>

typedef struct QuicMethod QUIC_METHOD;
typedef struct QuicCtx QUIC_CTX;
typedef struct Quic QUIC;
typedef struct QuicBuffer QUIC_BUFFER;
typedef struct QuicCipher QUIC_CIPHER;
typedef struct QuicCiphers QUIC_CIPHERS;
typedef struct QuicCrypto  QUIC_CRYPTO;
typedef enum QuicAlgId QUIC_ALG_ID;
typedef struct QuicDispenser QUIC_DISPENSER;
typedef int64_t QUIC_STREAM_HANDLE;
typedef struct QuicStreamIovec QUIC_STREAM_IOVEC;
typedef struct QuicSession QUIC_SESSION;

#endif
