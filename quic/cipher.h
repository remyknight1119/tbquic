#ifndef TBQUIC_QUIC_CIPHER_H_
#define TBQUIC_QUIC_CIPHER_H_

#include <tbquic/types.h>

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_MAX_SIZE    32

int QuicCreateInitialDecoders(QUIC *, uint32_t);
int QuicDoCipher(QUIC_CIPHER *, uint8_t *, size_t *, const uint8_t *, size_t);
void QuicCipherCtxFree(QUIC_CIPHERS *);
int QuicCipherNidFind(uint32_t);

#endif
