#ifndef TBQUIC_QUIC_TLS_TLS_LIB_H_
#define TBQUIC_QUIC_TLS_TLS_LIB_H_

#include "tls.h"

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

void TlsGetSupportedGroups(QUIC_TLS *, const uint16_t **, size_t *);
int TlsSetSupportedGroups(uint16_t **, size_t *, uint16_t *, size_t);
int TlsCheckFfdhGroup(uint16_t);
EVP_PKEY *TlsGeneratePkeyGroup(QUIC_TLS *tls, uint16_t id);

#endif