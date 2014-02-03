/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2013 Benjamin Fleischer
 */

#ifndef _DARWIN_COMPAT_
#define _DARWIN_COMPAT_

#include <pthread.h>

/* Semaphores */

typedef struct darwin_sem {
    int id;
    union {
        struct
        {
            unsigned int    count;
            pthread_mutex_t count_lock;
            pthread_cond_t  count_cond;
        } local;
    } __data;
} darwin_sem_t;

#define DARWIN_SEM_VALUE_MAX ((int32_t)32767)

int darwin_sem_init(darwin_sem_t *sem, int pshared, unsigned int value);
int darwin_sem_destroy(darwin_sem_t *sem);
int darwin_sem_getvalue(darwin_sem_t *sem, unsigned int *value);
int darwin_sem_post(darwin_sem_t *sem);
int darwin_sem_timedwait(darwin_sem_t *sem, const struct timespec *abs_timeout);
int darwin_sem_trywait(darwin_sem_t *sem);
int darwin_sem_wait(darwin_sem_t *sem);

/* Caller must not include <semaphore.h> */

typedef darwin_sem_t sem_t;

#define sem_init(s, p, v)   darwin_sem_init(s, p, v)
#define sem_destroy(s)      darwin_sem_destroy(s)
#define sem_getvalue(s, v)  darwin_sem_getvalue(s, v)
#define sem_post(s)         darwin_sem_post(s)
#define sem_timedwait(s, t) darwin_sem_timedwait(s, t)
#define sem_trywait(s)      darwin_sem_trywait(s)
#define sem_wait(s)         darwin_sem_wait(s)

#define SEM_VALUE_MAX       DARWIN_SEM_VALUE_MAX

#endif /* _DARWIN_COMPAT_ */
