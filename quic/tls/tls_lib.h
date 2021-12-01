#ifndef TBQUIC_QUIC_TLS_TLS_LIB_H_
#define TBQUIC_QUIC_TLS_TLS_LIB_H_

#include "tls.h"

typedef struct {
    int nid;                /* Curve NID */
    uint32_t secbits;       /* Bits of security (from SP800-57) */
} TlsGroupInfo;

void TlsGetSupportedGroups(QUIC_TLS *, const uint16_t **, size_t *);
int TlsSetSupportedGroups(uint16_t **, size_t *, int *, size_t);

#endif
