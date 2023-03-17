#ifndef _MY_THREADS_H_
#define _MY_THREADS_H_

#include <pthread.h>

typedef pthread_t thrd_t;
typedef void* (*pthread_compatible_routine)(void*);

#define thrd_create(thread, routine, argument) \
	pthread_create((thread), NULL, (pthread_compatible_routine) (routine), (argument));

#define thrd_join(thread, _ret) \
	pthread_join((thread), NULL);

#endif

