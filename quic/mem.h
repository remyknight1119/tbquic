#ifndef TBQUIC_QUIC_MEM_H_
#define TBQUIC_QUIC_MEM_H_

#include <stdlib.h>

void *QuicMemMalloc(size_t);
void *QuicMemCalloc(size_t);
void QuicMemFree(void *);
void *QuicMemDup(const void *, size_t);

#endif
