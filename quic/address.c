/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "address.h"

#include "mem.h"

bool AddressEqual(const Address *s1, const Address *s2)
{
    if (s1->addrlen != s2->addrlen) {
        return false; 
    }

    return (QuicMemCmp(&s1->addr, &s2->addr, s1->addrlen) == 0);
}

