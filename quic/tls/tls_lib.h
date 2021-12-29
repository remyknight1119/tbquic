#ifndef TBQUIC_QUIC_TLS_TLS_LIB_H_
#define TBQUIC_QUIC_TLS_TLS_LIB_H_

#include "tls.h"

#include <openssl/evp.h>

typedef struct {
    int nid;                /* Curve NID */
    uint32_t secbits;       /* Bits of security (from SP800-57) */
    /* flags type */
# define TLS_CURVE_PRIME         0x0
# define TLS_CURVE_CHAR2         0x1
# define TLS_CURVE_CUSTOM        0x2
# define TLS_CURVE_TYPE          0x3 /* Mask for group type */
    uint32_t flags;
} TlsGroupInfo;

void TlsGetSupportedGroups(TLS *, const uint16_t **, size_t *);
int TlsSetSupportedGroups(uint16_t **, size_t *, uint16_t *, size_t);
int TlsCheckFfdhGroup(uint16_t);
const EVP_MD *TlsHandshakeMd(TLS *);
EVP_PKEY *TlsGeneratePkeyGroup(TLS *, uint16_t);
int TlsDigestCachedRecords(TLS *);
int TlsFinishMac(TLS *, const uint8_t *, size_t);
int TlsHandshakeHash(TLS *, const EVP_MD *, uint8_t *);
int TlsDeriveSecrets(TLS *, const EVP_MD *, const uint8_t *, const uint8_t *,
                        size_t, const uint8_t *, uint8_t *);
int TlsGenerateSecret(const EVP_MD *, const uint8_t *, const uint8_t *, size_t,
                        uint8_t *);
int TlsKeyDerive(TLS *, EVP_PKEY *, EVP_PKEY *);

#endif
