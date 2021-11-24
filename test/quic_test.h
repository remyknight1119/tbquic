#ifndef TBQUIC_TEST_QUIC_TEST_H_
#define TBQUIC_TEST_QUIC_TEST_H_

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define ARRAY_SIZE(array)    (sizeof(array)/sizeof(array[0]))

typedef union UdpConnKey {
	struct sockaddr 		addr;
	struct sockaddr_in  	addr4;
	struct sockaddr_in6  	addr6;
} QuicUdpConnKey;

extern char *quic_cert;
extern char *quic_key;

int QuicVariableLengthDecodeTest(void);
int QuicHkdfExtractExpandTest(void);
int QuicHkdfExpandLabel(void);
int QuicPktFormatTestClient(void);
int QuicPktFormatTestServer(void);
int QuicPktNumberEncodeTest(void);
int QuicPktNumberDecodeTest(void);
int QuicVTlsCipherListTest(void);
int QuicTlsClientHelloTest(void);

#endif
