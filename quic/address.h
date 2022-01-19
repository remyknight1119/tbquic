#ifndef TBQUIC_QUIC_ADDRESS_H_ 
#define TBQUIC_QUIC_ADDRESS_H_ 

#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
    union {
        struct sockaddr 		addr;
        struct sockaddr_in  	addr4;
        struct sockaddr_in6  	addr6;
    };
    socklen_t addrlen;
} Address;

bool AddressEqual(const Address *, const Address *);

#endif
