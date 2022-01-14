#ifndef TBQUIC_QUIC_COMMON_H_
#define TBQUIC_QUIC_COMMON_H_

#include <stddef.h>
#include <stdio.h>

#define QUIC_NELEM(x)    (sizeof(x)/sizeof(x[0]))

/*
 * QUIC_CONTAINER_OF - cast a member of a structure out to the containing structure
 * @ptr:    the pointer to the member.
 * @type:   the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define QUIC_CONTAINER_OF(ptr, type, member) ({          \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})


#define QUIC_LT(a, b) ((int)((a) - (b)) < 0)
#define QUIC_GT(a, b) ((int)((a) - (b)) > 0)
#define QUIC_LE(a, b) ((int)((a) - (b)) <= 0)
#define QUIC_GE(a, b) ((int)((a) - (b)) >= 0)

#define QUIC_MIN(a, b) (QUIC_GT(a, b) ? b : a)
#define QUIC_MAX(a, b) (QUIC_GT(a, b) ? a : b)

#define QuicPrint(data, len) \
    do { \
        QuicPrintData(data, len, __FILE__, __LINE__, __FUNCTION__); \
    } while (0)

static inline void QuicPrintData(const uint8_t *data, size_t len,
                    const char *file, int line, const char *func)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02X", data[i]);
    }

    fprintf(stdout, "\n[%s %d: %s] len = %lu\n", file, line, func, len);
}


#endif
