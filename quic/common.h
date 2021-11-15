#ifndef TBQUIC_QUIC_COMMON_H_
#define TBQUIC_QUIC_COMMON_H_

#define QUIC_ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

#define QUIC_LT(a, b) ((int)(a - b) < 0)
#define QUIC_GT(a, b) ((int)(a - b) > 0)

static inline void QuicPrint(const uint8_t *data, size_t len)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02X", data[i]);
    }

    fprintf(stdout, "\nlen = %lu\n", len);
}


#endif
