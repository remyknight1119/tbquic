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

int QuicVariableLengthDecodeTest(void);
int QuicHkdfExtractExpandTest(void);
int QuicHkdfExpandLabel(void);
int QuicPktFormatTest(void);
int QuicPktNumberDecodeTest(void);

#endif
