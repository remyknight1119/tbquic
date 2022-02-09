/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "quic_time.h"

#include <stddef.h>
#include <sys/time.h>

uint64_t QuicGetTimeUs(void)
{
	struct timeval  t = {};

	gettimeofday(&t, NULL);

	return (t.tv_sec*1000000 + t.tv_usec);
}


