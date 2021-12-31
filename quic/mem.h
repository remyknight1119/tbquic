#ifndef TBQUIC_QUIC_MEM_H_
#define TBQUIC_QUIC_MEM_H_

#include <stdlib.h>

void *QuicMemMalloc(size_t);
void *QuicMemCalloc(size_t);
void QuicMemFree(void *);
void *QuicMemcpy(void *, const void *, size_t);
void *QuicMemDup(const void *, size_t);
char *QuicMemStrDup(const char *);
void *QuicMemmove(void *, const void *, size_t);
void *QuicMemset(void *, int, size_t);
int QuicMemCmp(const void *, const void *, size_t);

#endif
