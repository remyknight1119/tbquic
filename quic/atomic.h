#ifndef TBQUIC_QUIC_ATOMIC_H_
#define TBQUIC_QUIC_ATOMIC_H_

#define atomic_add(i, v)		__sync_fetch_and_add(v, i)
#define atomic_sub(i, v)  		__sync_fetch_and_sub(v, i)
#define atomic_cmpxchg(v, o, n) __sync_bool_compare_and_swap(v, o, n)
#define atomic_inc(v)  			atomic_add(1, v)
#define atomic_dec(v)  			atomic_sub(1, v)
#define atomic_set(v, i)    	(*v = i)
#define atomic_read(v)          (*(volatile int *)v)

#define atomic_and(i, v)  		__sync_fetch_and_and(v, i)
#define atomic_or(i, v)  		__sync_fetch_and_or(v, i)

#define atomic64_add(i, v)		__sync_fetch_and_add(v, i)
#define atomic64_sub(i, v)  	__sync_fetch_and_sub(v, i)
#define atomic64_inc(v)  		atomic64_add(1, v)
#define atomic64_dec(v)  		atomic64_sub(1, v)
#define atomic64_set(v, i)    	(*v = i)
#define atomic64_read(v)        (*(volatile long *)v)

#endif
