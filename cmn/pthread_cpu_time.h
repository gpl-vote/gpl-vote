/* 
 * File:   pthread_cpu_time.h
 * Author: zhenka
 *
 * Created on 15 Декабрь 2011 г., 21:30
 *
 * Link with "-lrt" 
 */

#ifndef PTHREAD_CPU_TIME_H
#define	PTHREAD_CPU_TIME_H

#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include "../cmn/exception.h"

inline timespec get_pthread_time_mark(const pthread_t thread = pthread_self())
{
    clockid_t cid;
    timespec ts;
    int ret = pthread_getcpuclockid(thread, &cid);
    if (ret != 0) throw cmn::exception( "Exception: pthread_getcpuclockid" );
    if (clock_gettime(cid, &ts) == -1) throw;
    return ts;
}

inline int64_t get_time_diff_nsec(const timespec& b, const timespec& e)
{
    return (e.tv_sec*1000000 + e.tv_nsec) - (b.tv_sec*1000000 + b.tv_nsec);
}

inline int32_t get_time_diff_sec(const timespec& b, const timespec& e)
{
    return e.tv_sec - b.tv_sec;
}


#endif	/* PTHREAD_CPU_TIME_H */

