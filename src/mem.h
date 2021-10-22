#ifndef TBQUIC_SRC_MEM_H_
#define TBQUIC_SRC_MEM_H_

#include <stdlib.h>

void *QuicMemMalloc(size_t size);
void *QuicMemCalloc(size_t size);
void QuicMemFree(void *ptr);

#endif
