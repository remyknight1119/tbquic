
#include "quic_test.h"

#include <tbquic/types.h>
#include <tbquic/stream.h>

void QuicTestStreamIovecInit(QUIC_STREAM_IOVEC *iov, QuicTestBuff *buf,
                                size_t num)
{
    size_t i = 0;

    for (i = 0; i < num; i++) {
        iov[i].iov_base = buf[i].buf;
        iov[i].iov_len = sizeof(buf[i].buf);
    }
}
