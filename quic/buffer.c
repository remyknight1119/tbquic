#include "buffer.h"

#include "mem.h"

QuicBufMem *QuicBufNew(void)
{
    QuicBufMem *buf = NULL;

    buf = QuicMemCalloc(sizeof(*buf));

    return buf;
}

void QuicBufFree(QuicBufMem *buf)
{
    if (buf == NULL) {
        return;
    }

    QuicMemFree(buf);
}
