#ifndef TBQUIC_QUIC_TLS_EXTENSION_H_
#define TBQUIC_QUIC_TLS_EXTENSION_H_

#include <openssl/x509.h>

#include "tls.h"
#include "packet_local.h"

#define TLSEXT_CLIENT_HELLO    0x0001
#define TLSEXT_SERVER_HELLO    0x0002

/* Sigalgs values */
#define TLSEXT_SIGALG_ECDSA_SECP256R1_SHA256                    0x0403
#define TLSEXT_SIGALG_ECDSA_SECP384R1_SHA384                    0x0503
#define TLSEXT_SIGALG_ECDSA_SECP521R1_SHA512                    0x0603
#define TLSEXT_SIGALG_ECDSA_SHA224                              0x0303
#define TLSEXT_SIGALG_ECDSA_SHA1                                0x0203
#define TLSEXT_SIGALG_RSA_PSS_RSAE_SHA256                       0x0804
#define TLSEXT_SIGALG_RSA_PSS_RSAE_SHA384                       0x0805
#define TLSEXT_SIGALG_RSA_PSS_RSAE_SHA512                       0x0806
#define TLSEXT_SIGALG_RSA_PSS_PSS_SHA256                        0x0809
#define TLSEXT_SIGALG_RSA_PSS_PSS_SHA384                        0x080a
#define TLSEXT_SIGALG_RSA_PSS_PSS_SHA512                        0x080b
#define TLSEXT_SIGALG_RSA_PKCS1_SHA256                          0x0401
#define TLSEXT_SIGALG_RSA_PKCS1_SHA384                          0x0501
#define TLSEXT_SIGALG_RSA_PKCS1_SHA512                          0x0601
#define TLSEXT_SIGALG_RSA_PKCS1_SHA224                          0x0301
#define TLSEXT_SIGALG_RSA_PKCS1_SHA1                            0x0201

typedef enum {
    EXT_TYPE_SERVER_NAME = 0,                             /* RFC 6066 */
    EXT_TYPE_MAX_FRAGMENT_LENGTH = 1,                     /* RFC 6066 */
    EXT_TYPE_STATUS_REQUEST = 5,                          /* RFC 6066 */
    EXT_TYPE_SUPPORTED_GROUPS = 10,                       /* RFC 8422, 7919 */
    EXT_TYPE_SIGNATURE_ALGORITHMS = 13,                   /* RFC 8446 */
    EXT_TYPE_USE_SRTP = 14,                               /* RFC 5764 */
    EXT_TYPE_HEARTBEAT = 15,                              /* RFC 6520 */
    EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16, /* RFC 7301 */
    EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP = 18,           /* RFC 6962 */
    EXT_TYPE_CLIENT_CERTIFICATE_TYPE = 19,                /* RFC 7250 */
    EXT_TYPE_SERVER_CERTIFICATE_TYPE = 20,                /* RFC 7250 */
    EXT_TYPE_PADDING = 21,                                /* RFC 7685 */
    EXT_TYPE_PRE_SHARED_KEY = 41,                         /* RFC 8446 */
    EXT_TYPE_EARLY_DATA = 42,                             /* RFC 8446 */
    EXT_TYPE_SUPPORTED_VERSIONS = 43,                     /* RFC 8446 */
    EXT_TYPE_COOKIE = 44,                                 /* RFC 8446 */
    EXT_TYPE_PSK_KEY_EXCHANGE_MODES = 45,                 /* RFC 8446 */
    EXT_TYPE_CERTIFICATE_AUTHORITIES = 47,                /* RFC 8446 */
    EXT_TYPE_OID_FILTERS = 48,                            /* RFC 8446 */
    EXT_TYPE_POST_HANDSHAKE_AUTH = 49,                    /* RFC 8446 */
    EXT_TYPE_SIGNATURE_ALGORITHMS_CERT = 50,              /* RFC 8446 */
    EXT_TYPE_KEY_SHARE = 51,                              /* RFC 8446 */
    EXT_TYPE_QUIC_TRANS_PARAMS = 57,                      /* RFC 9001 */
    EXT_TYPE_MAX = 65535,
} ExtensionType;


typedef struct {
    /*
     * The context that this extension applies to, e.g. what messages and
     * protocol versions
     */
    uint32_t context;
    /*
     * Initialise extension before parsing. Always called for relevant contexts
     * even if extension not present
     */
    int (*init)(QUIC_TLS *tls, uint32_t context);
    /* Parse extension */
    int (*parse)(QUIC_TLS *tls, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx);
    /* Check if need construct */
    int (*check)(QUIC_TLS *tls);
    /* Construct extension */
    int (*construct)(QUIC_TLS *tls, WPacket *pkt, uint32_t context, X509 *x,
                                    size_t chainidx);
    /*
     * Finalise extension after parsing. Always called where an extensions was
     * initialised even if the extension was not present. |sent| is set to 1 if
     * the extension was seen, or 0 otherwise.
     */
    int (*final)(QUIC_TLS *tls, uint32_t context, int sent);
} QuicTlsExtensionDefinition;

typedef struct {
    uint64_t type;
    int (*parse)(QuicTransParams *param, RPacket *pkt);
    /* Check if need construct */
    int (*check)(QuicTransParams *param, size_t offset);
    int (*construct)(QuicTransParams *param, size_t offset, WPacket *pkt);
} QuicTransParamDefinition;

#ifdef QUIC_TEST
extern const QuicTlsExtensionDefinition *(*QuicTestExtensionHook)(const
        QuicTlsExtensionDefinition *, size_t *i);
extern QuicTransParamDefinition *
(*QuicTestTransParamHook)(QuicTransParamDefinition *, size_t);
#endif

int TlsExtInitServerName(QUIC_TLS *, uint32_t);
int TlsExtFinalServerName(QUIC_TLS *, uint32_t, int);
int TlsExtInitSigAlgs(QUIC_TLS *, uint32_t);
int TlsExtFinalSigAlgs(QUIC_TLS *, uint32_t, int);

int TlsConstructExtensions(QUIC_TLS *, WPacket *, uint32_t, X509 *, size_t,
                             const QuicTlsExtensionDefinition *ext,
                             size_t);
int TlsConstructQuicTransParamExtension(QUIC_TLS *, WPacket *,
                            QuicTransParamDefinition *, size_t);
int TlsClientConstructExtensions(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                            size_t);
int QuicTransParamCheckInteger(QuicTransParams *, size_t);
int QuicTransParamConstructInteger(QuicTransParams *, size_t, WPacket *);

#endif