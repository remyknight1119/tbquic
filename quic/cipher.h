#ifndef TBQUIC_QUIC_CIPHER_H_
#define TBQUIC_QUIC_CIPHER_H_

#include <tbquic/types.h>

#include <stdint.h>

#define AES_KEY_MAX_SIZE    32

int QuicCreateInitialDecoders(QUIC *, uint32_t);
int QuicCipherEncrypt(QUIC_CIPHER *, uint8_t *, int *, const uint8_t *, int);
void QuicCipherCtxFree(QUIC_CIPHERS *);

#endif
