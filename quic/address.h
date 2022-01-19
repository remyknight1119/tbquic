#ifndef TBQUIC_QUIC_ADDRESS_H_ 
#define TBQUIC_QUIC_ADDRESS_H_ 

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    union {
        struct sockaddr 		in;
        struct sockaddr_in  	in4;
        struct sockaddr_in6  	in6;
    } addr;
    socklen_t addrlen;
} Address;

bool AddressEqual(const Address *, const Address *);

#endif
