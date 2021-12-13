#ifndef TBQUIC_QUIC_TLS_TLS_CIPHER_H_
#define TBQUIC_QUIC_TLS_TLS_CIPHER_H_

#include <stdint.h>

#include "list.h"
#include "packet_local.h"

#define TLS_CIPHERS_SEP ":"

#define TLS_RFC_AES_128_GCM_SHA256                   "TLS_AES_128_GCM_SHA256"
#define TLS_RFC_AES_256_GCM_SHA384                   "TLS_AES_256_GCM_SHA384"
#define TLS_RFC_CHACHA20_POLY1305_SHA256             "TLS_CHACHA20_POLY1305_SHA256"
#define TLS_RFC_AES_128_CCM_SHA256                   "TLS_AES_128_CCM_SHA256"
#define TLS_RFC_AES_128_CCM_8_SHA256                 "TLS_AES_128_CCM_8_SHA256"

#define TLS_CIPHERS_DEF \
    TLS_RFC_AES_128_GCM_SHA256 TLS_CIPHERS_SEP TLS_RFC_AES_256_GCM_SHA384 \
    TLS_CIPHERS_SEP TLS_RFC_CHACHA20_POLY1305_SHA256

#define TLS_CK_AES_128_GCM_SHA256                     0x1301
#define TLS_CK_AES_256_GCM_SHA384                     0x1302
#define TLS_CK_CHACHA20_POLY1305_SHA256               0x1303
#define TLS_CK_AES_128_CCM_SHA256                     0x1304
#define TLS_CK_AES_128_CCM_8_SHA256                   0x1305

/* Bits for algorithm_mkey (key exchange algorithm) */

#define TLS_K_ANY                0x00000000U
/* RSA key exchange */
#define TLS_K_RSA                0x00000001U
/* ephemeral ECDH */
#define TLS_K_ECDHE              0x00000002U

/* Bits for algorithm_auth (server authentication) */

#define TLS_A_ANY                0x00000000U
/* RSA auth */
#define TLS_A_RSA                0x00000001U
/* ECDSA auth*/
#define TLS_A_ECDSA              0x00000002U


typedef struct {
    const char *name;           /* text name */
    uint16_t id;                /* id */
    uint32_t algorithm_enc;     /* symmetric encryption */
    uint32_t alg_bits;          /* Number of bits for algorithm */
    uint32_t digest;
    uint32_t strength_bits;     /* Number of bits really used */
} TlsCipher;

typedef struct {
    struct hlist_node node;
    const TlsCipher *cipher;
} TlsCipherListNode;

const TlsCipher *QuicGetTlsCipherByName(const char *, size_t);
const TlsCipher *QuicGetTlsCipherById(uint16_t);
int QuicTlsParseCipherList(struct hlist_head *, RPacket *, size_t);
int QuicTlsCreateCipherList(struct hlist_head *, const char *, size_t);
void QuicTlsDestroyCipherList(struct hlist_head *);

#endif
