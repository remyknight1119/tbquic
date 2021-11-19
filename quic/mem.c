/*
 * Remy Lewis(remyknight1119@gmail.com)
 */
#include "mem.h"

#include <string.h>

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
    if (ptr == NULL) {
        return;
    }

    free(ptr);
}

void *QuicMemDup(const void *ptr, size_t size)
{
    void *m = NULL;
    
    m = QuicMemMalloc(size);
    if (m == NULL) {
        return NULL;
    }

    memcpy(m, ptr, size);
    return m;
}

void *QuicMemmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}
