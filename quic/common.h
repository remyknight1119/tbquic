#ifndef TBQUIC_QUIC_COMMON_H_
#define TBQUIC_QUIC_COMMON_H_

#include <stddef.h>

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

static inline void QuicPrint(const uint8_t *data, size_t len)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02X", data[i]);
    }

    fprintf(stdout, "\nlen = %lu\n", len);
}


#endif
