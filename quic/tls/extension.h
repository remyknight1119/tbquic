#ifndef TBQUIC_QUIC_TLS_EXTENSION_H_
#define TBQUIC_QUIC_TLS_EXTENSION_H_

#include <openssl/x509.h>

#include "tls.h"
#include "packet_local.h"

#define TLS_EXT_CLIENT_HELLO    0x0001
#define TLS_EXT_SERVER_HELLO    0x0002

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
    EXT_TYPE_MAX = 65535,
} ExtensionType;

typedef int (*ExtensionParse)(QUIC_TLS *quic, RPacket *pkt, uint32_t context,
                                X509 *x, size_t chainidx);
typedef int (*ExtensionConstruct)(QUIC_TLS *quic, WPacket *pkt,
                                    uint32_t context, X509 *x,
                                    size_t chainidx);

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
    int (*init)(QUIC_TLS *quic, uint32_t context);
    /* Parse extension sent from client to server */
    ExtensionParse parse_ctos;
    /* Parse extension send from server to client */
    ExtensionParse parse_stoc;
    /* Construct extension sent from server to client */
    ExtensionConstruct construct_stoc;
    /* Construct extension sent from client to server */
    ExtensionConstruct construct_ctos;
    /*
     * Finalise extension after parsing. Always called where an extensions was
     * initialised even if the extension was not present. |sent| is set to 1 if
     * the extension was seen, or 0 otherwise.
     */
    int (*final)(QUIC_TLS *quic, uint32_t context, int sent);
} QuicTlsExtensionDefinition;

int TlsExtParseStocServerName(QUIC_TLS *, RPacket *, uint32_t, X509 *, size_t);
int TlsExtConstructCtosServerName(QUIC_TLS *, WPacket *, uint32_t, X509 *,
                                    size_t);
int TlsConstructExtensions(QUIC_TLS *, WPacket *, uint32_t, X509 *, size_t);

#endif
