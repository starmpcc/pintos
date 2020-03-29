#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
//list를 사용하기 위해서 추가함.
#include <list.h>


/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

void timer_print_stats (void);

/*
	sleep tuple
	스레드가 언제 깨어나야 하는지에 관한 정보를 저장함.
*/
struct sleep_tuple {
	// 스레드가 깨어날 시간
	int64_t wakeup_tick;
	//sleep 상태인 스레드
	struct thread* thread;
	// list에 저장하기 위한 elem
	struct list_elem elem;
};

#endif /* devices/timer.h */
