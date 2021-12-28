#ifndef TBQUIC_QUIC_TLS_EXTENSION_H_
#define TBQUIC_QUIC_TLS_EXTENSION_H_

#include <openssl/x509.h>

#include "tls.h"
#include "packet_local.h"

#define TLSEXT_CLIENT_HELLO    0x0001
#define TLSEXT_SERVER_HELLO    0x0002
#define TLSEXT_CERTIFICATE     0x0004

#define TLSEXT_KEX_MODE_KE_DHE     0x01

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
    uint16_t type;
    /*
     * The context that this extension applies to, e.g. what messages and
     * protocol versions
     */
    uint32_t context;
    /* Check if need construct */
    int (*check)(QUIC_TLS *tls);
    /* Construct extension */
    int (*construct)(QUIC_TLS *tls, WPacket *pkt, uint32_t context, X509 *x,
                                    size_t chainidx);
} QuicTlsExtConstruct;

typedef struct {
    uint16_t type;
    /*
     * The context that this extension applies to, e.g. what messages and
     * protocol versions
     */
    uint32_t context;
    /* Parse extension */
    int (*parse)(QUIC_TLS *tls, RPacket *pkt, uint32_t context, X509 *x,
                    size_t chainidx);
} QuicTlsExtParse;

typedef struct {
    uint64_t type;
    int (*parse)(QUIC_TLS *tls, QuicTransParams *param, size_t offset,
                        RPacket *pkt, uint64_t len);
    /* Check if need construct */
    int (*check)(QUIC_TLS *tls, QuicTransParams *param, size_t offset);
    int (*construct)(QUIC_TLS *tls, QuicTransParams *param, size_t offset,
                        WPacket *pkt);
} TlsExtQtpDefinition;

#ifdef QUIC_TEST
extern const QuicTlsExtConstruct *(*QuicTestExtensionHook)(const
        QuicTlsExtConstruct *, size_t);
extern const TlsExtQtpDefinition *
(*QuicTestTransParamHook)(const TlsExtQtpDefinition *, size_t);
extern size_t (*QuicTestEncodedpointHook)(unsigned char **point);
#endif

int TlsExtInitServerName(QUIC_TLS *, uint32_t);
int TlsExtFinalServerName(QUIC_TLS *, uint32_t, int);
int TlsExtInitSigAlgs(QUIC_TLS *, uint32_t);
int TlsExtFinalSigAlgs(QUIC_TLS *, uint32_t, int);

int TlsConstructExtensions(QUIC_TLS *, WPacket *, uint32_t, X509 *, size_t,
                             const QuicTlsExtConstruct *, size_t);
int TlsParseExtensions(QUIC_TLS *, RPacket *, uint32_t, X509 *, size_t,
                             const QuicTlsExtParse *, size_t);
int TlsConstructQtpExtension(QUIC_TLS *, WPacket *, const TlsExtQtpDefinition *,
                            size_t);
int TlsParseQtpExtension(QUIC_TLS *, QuicTransParams *, RPacket *,
                                const TlsExtQtpDefinition *, size_t);
int TlsClientConstructExtensions(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                            size_t);
int TlsClientParseExtensions(QUIC_TLS *, RPacket *, uint32_t, X509 *, size_t);
int TlsExtQtpCheckInteger(QUIC_TLS *, QuicTransParams *, size_t);
int TlsExtQtpConstructInteger(QUIC_TLS *, QuicTransParams *, size_t,
                                    WPacket *);
int TlsExtQtpParseInteger(QUIC_TLS *, QuicTransParams *, size_t,
                                    RPacket *, uint64_t);

#endif
