#ifndef TBQUIC_QUIC_MEM_H_
#define TBQUIC_QUIC_MEM_H_

#include <stdlib.h>

void *QuicMemMalloc(size_t size);
void *QuicMemCalloc(size_t size);
void QuicMemFree(void *ptr);

#endif
