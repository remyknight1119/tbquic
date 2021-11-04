#ifndef TBQUIC_QUIC_CIPHER_H_
#define TBQUIC_QUIC_CIPHER_H_

#include <tbquic/types.h>

#include <stdint.h>

int QuicCreateInitialDecoders(QUIC *quic, uint32_t version);

#endif
