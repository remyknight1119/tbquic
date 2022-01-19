#ifndef TBQUIC_QUIC_LOG_H_
#define TBQUIC_QUIC_LOG_H_

#include <stdio.h>
#include <errno.h>

#define QUIC_DEBUG 1

#define QUIC_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)


#endif
