#ifndef TBQUIC_QUIC_ASN1_H_
#define TBQUIC_QUIC_ASN1_H_

#include <stdio.h>
#include <stdlib.h>
#include <openssl/asn1t.h>

#include "session.h"

typedef struct {
    uint32_t cipher_id;
    uint32_t tick_age_add;
    uint64_t tick_lifetime_hint;
    ASN1_OCTET_STRING *tlsext_tick;
} QUIC_SESSION_ASN1;

int i2dQuicSession(QUIC_SESSION *in, uint8_t **pp);
QUIC_SESSION *d2iQuicSession(const uint8_t **pp, long length);

#endif
