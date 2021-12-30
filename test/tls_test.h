#ifndef TBQUIC_TEST_TLS_TEST_H_
#define TBQUIC_TEST_TLS_TEST_H_

#include <string.h>
#include "quic_test.h"

static const char *TlsFindServerHello(const char *start, size_t total_len)
{
    char *sub_str = "010000";
    const char *curr = start;
    uint8_t length = 0;

    curr = start + strlen(sub_str);
    str2hex(&length, (void *)curr, sizeof(length));

    return curr + 2 + 2*length;
}

#endif
