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

void *QuicMemcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

void *QuicMemDup(const void *ptr, size_t size)
{
    void *m = NULL;
    
    if (ptr == NULL) {
        return NULL;
    }

    m = QuicMemMalloc(size);
    if (m == NULL) {
        return NULL;
    }

    QuicMemcpy(m, ptr, size);
    return m;
}

char *QuicMemStrDup(const char *str)
{
    char *dst = NULL;

    if (str == NULL) {
        return NULL;
    }

    dst = QuicMemMalloc(strlen(str) + 1);
    if (dst == NULL) {
        return NULL;
    }

    strcpy(dst, str);
    return dst;
}

void *QuicMemmove(void *dest, const void *src, size_t n)
{
    return memmove(dest, src, n);
}

void *QuicMemset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

int QuicMemCmp(const void *s1, const void *s2, size_t n)
{
    return memcmp(s1, s2, n);
}


