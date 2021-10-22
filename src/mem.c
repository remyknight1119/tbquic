
#include "mem.h"

void *QuicMemMalloc(size_t size)
{
    return malloc(size);
}

void *QuicMemCalloc(size_t size)
{
    return calloc(1, size);
}

void QuicMemFree(void *ptr)
{
    free(ptr);
}
