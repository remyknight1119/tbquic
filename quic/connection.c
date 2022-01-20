/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "connection.h"

void QuicConnFree(QuicConn *c)
{
    QuicDataFree(&c->id);
}
