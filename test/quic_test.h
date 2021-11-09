#ifndef TBQUIC_TEST_QUIC_TEST_H_
#define TBQUIC_TEST_QUIC_TEST_H_

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef union UdpConnKey {
	struct sockaddr 		addr;
	struct sockaddr_in  	addr4;
	struct sockaddr_in6  	addr6;
} QuicUdpConnKey;

typedef struct {
    uint8_t *data;
    size_t len;
} QuicData;

static inline void QuicPrint(uint8_t *data, size_t len)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02x", data[i]);
    }

    fprintf(stdout, "\nlen = %lu\n", len);
}

int QuicVariableLengthDecodeTest(void);
int QuicHkdfExtractTest(void);

#endif
