#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

static struct priority_bucket* priority_buckets;

/* Used to synchronize shared state children_info_lock */
struct lock children_info_lock;
static struct list children_info;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

static int fp_tofp (int n);
static int fp_toint_lound_zero (int x);
static int fp_toint_lound_near (int x);
static int fp_add (int x, int y);
static int fp_sub (int x, int y);
static int fp_mul (int x, int y);
static int fp_div (int x, int y);


static int thread_active = 0;
static void thread_calc_recent_cpu(struct thread* t);
static void thread_calc_load_avg (void);
static void thread_calc_priority(struct thread* t);
static struct list blocked_list;
static int load_avg = 0;
static void thread_recalc(void);
//var mlfqs to make exception when create new thread
/* Auxiliary comparator for sorted insert to ready_list. */
static bool bucket_pointer_more (const struct list_elem *, const struct list_elem *, void*);
extern struct lock filesys_lock;
static bool lock_priority_less (const struct list_elem *, const struct list_elem *, void*);
/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)

/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))

#define MAX(x, y) (((x) > (y)) ? (x) : (y))

// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);
//	int i;

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	list_init (&children_info);
	lock_init (&children_info_lock);
	list_init (&blocked_list);
	lock_init(&filesys_lock);
	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	size_t req_bucket_space = sizeof(struct priority_bucket) * 64;
	size_t req_page_cnt = DIV_ROUND_UP (req_bucket_space, PGSIZE);
	priority_buckets = (struct priority_bucket *) palloc_get_multiple(PAL_ZERO, req_page_cnt);
	for (int i = 0; i < NUM_PRI; i++)
		list_init (&priority_buckets[i].bucket);

	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

void thread_recalc(void){
	struct thread *curr = running_thread ();
	//mlfqs ??????????????? ??? ?????? ???????????? ????????? ???????????? ?????????
	if (thread_mlfqs && thread_active){
		//load_avg  ??? recent_cpu??? 100????????? ????????????.
		if (timer_ticks()%TIMER_FREQ==0){
			thread_calc_load_avg();
			//?????? ???????????? recent_cpu ????????????
			if (curr!= idle_thread) thread_calc_recent_cpu(curr);
			//blocked list ?????? block??? ???????????? ????????????
			if (!list_empty(&blocked_list)){
				for (struct list_elem* i = list_front(&blocked_list); i!=list_end(&blocked_list); i = list_next(i) ){
					struct thread* t = list_entry(i, struct thread, elem2);
					ASSERT(is_thread(t));
					thread_calc_recent_cpu(t);
				}
			}
			//ready_list ?????? ???????????? ????????????
			if (!list_empty(&ready_list)){
				for (struct list_elem* i = list_front(&ready_list); i!=list_end(&ready_list); i = list_next(i) ){
					struct list* l = &list_entry(i, struct priority_bucket, elem)->bucket;
					ASSERT(!list_empty(l));
					for (struct list_elem* j = list_front (l); j != list_end(l); j = list_next(j)){
						struct thread* t = list_entry(j, struct thread, elem);
						ASSERT(is_thread(t));
						thread_calc_recent_cpu(t);
					}
				}

			}
		}

		//4????????? priority ?????? ?????????
		if (timer_ticks()%4 == 0 && thread_active >0){
			//?????? ????????? ?????????
			if (curr!= idle_thread) thread_calc_priority(curr);
			//blocked list ?????????
			if (!list_empty(&blocked_list)){
				for (struct list_elem* i = list_front(&blocked_list); i!=list_end(&blocked_list); i = list_next(i) ){
					struct thread* t = list_entry(i, struct thread, elem2);
					ASSERT(is_thread(t));
					thread_calc_priority(t);
				}
			}
			struct thread* thread_list[64];
			int k=0;
			//ready_list ?????????, ??? ???, ????????? ?????? ??? ???????????? ?????? ?????? ?????? ???????????? ???????????? ????????????.
			if (!list_empty(&ready_list)){
				for (struct list_elem* i = list_front(&ready_list); i!=list_end(&ready_list); i = list_next(i) ){
					struct list* l = &list_entry(i, struct priority_bucket, elem)->bucket;
					ASSERT(!list_empty(l));
					for (struct list_elem* j = list_front (l); j != list_end(l); j = list_next(j)){
						struct thread* t = list_entry(j, struct thread, elem);
						ASSERT(is_thread(t));
						thread_list[k] = t;
					}
				}
				//ready_list ?????? ?????? ????????? ???????????? ?????? priority ?????????
				for (int i=0;i<k;i++){
						struct thread* t = thread_list[i];
						ASSERT(t->status == THREAD_READY);
						bucket_remove(t);
						thread_calc_priority(t);
						bucket_push(t);
				}
			}
		}	
	}

}
/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {

	struct thread *curr = thread_current ();
	thread_recalc();
	if(curr!=idle_thread){
			curr->recent_cpu+=fp_tofp(1);
	}

	/* Update statistics. */
	if (curr == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (curr->pml4 != NULL)
		user_ticks++;
#endif
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
		intr_yield_on_return ();
}


/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	if (thread_mlfqs){
		t->priority = PRI_DEFAULT;
		if (thread_current()!=idle_thread){
			t->nice = thread_current()->nice;
			t->recent_cpu = thread_current()->recent_cpu;
			thread_calc_priority(t);
		}
		thread_active++;
	} 
	t->fd_max=1;
	if (thread_current()->tid != 1 && thread_current()->tid != 0){
		t->fd_max = thread_current()->fd_max;
		t->current_dir = thread_current()->current_dir;
	}
	/* Add to run queue. */
	thread_unblock (t);

	/* Yield running thread to apply possible priority change
	 * due to newly created thread. */
	thread_yield ();


	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	struct thread* t=  thread_current();
	t->status = THREAD_BLOCKED;
	if (thread_mlfqs && t!=idle_thread){

		t->block_unblock=1;
		list_push_back(&blocked_list,&t->elem2);
	}
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);


	if (thread_mlfqs && t->block_unblock==1 && t!=idle_thread){
		list_remove(&t->elem2);
		t->block_unblock=0;
	}
	bucket_push (t);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());
#ifdef USERPROG
	process_exit ();
#endif
	struct thread *curr = thread_current ();
	// Cleanup lock related
	struct lock *acquired_lock;
	struct list_elem *i;
	if (!list_empty (&curr->acquired_locks))
	{
		for (i = list_front (&curr->acquired_locks); i != list_end (&curr->acquired_locks); i = list_next (i))
		{
			acquired_lock = list_entry (i, struct lock, elem);
			lock_release (acquired_lock);
		}
	}

	if (curr->blocking_lock != NULL) {
		list_remove (&curr->elem);
	}


	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		bucket_push (curr);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) {
	if (thread_mlfqs) return;
	int old_priority = thread_current ()->priority;
	thread_current ()->priority = new_priority;
	if (old_priority > new_priority)
		// Lowering priority requires immediate yield
		thread_yield ();
}

/* Returns the given thread's priority. */
int
thread_get_priority_of (struct thread* t) {
	ASSERT(is_thread(t));
	int donated_priority = 0;
	if (!list_empty (&t->acquired_locks))
	{
		// pick highest max_donated_priority from acquired_locks.
		struct list_elem *highest = list_max (&t->acquired_locks, lock_priority_less, NULL);
		struct lock *lock = list_entry (highest, struct lock, elem);
		donated_priority = lock->max_donated_priority;
	}
	return MAX(t->priority, donated_priority);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	return thread_get_priority_of (thread_current ());
}

void
thread_calc_priority(struct thread* t){
	int priority = fp_toint_lound_zero(fp_tofp(PRI_MAX) - t->recent_cpu/4 - fp_tofp(t->nice *2));
	priority = PRI_MIN > priority ? PRI_MIN : priority;
	priority = PRI_MAX < priority ? PRI_MAX : priority;
	t->priority = priority;

}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	//nice??? int??? ??????
	struct thread* t = thread_current();
	t->nice = nice;
	thread_calc_priority(t);
	if (!list_empty(&ready_list)){
		struct priority_bucket* highest_priority_bucket = list_entry (list_front (&ready_list), struct priority_bucket, elem);
		ASSERT (!list_empty (&highest_priority_bucket->bucket));
		struct thread *high = list_entry (list_front (&highest_priority_bucket->bucket), struct thread, elem);
		if (t->priority < high->priority) thread_yield();
	}
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	//load_avg??? int??? 100??? ?????? ??????
	return fp_toint_lound_near (load_avg * 100);
}

void
thread_calc_load_avg (void){
	//?????? FP 59/60, 1/60
	int c1 = fp_tofp(59) / 60;
	int c2 = fp_tofp(1) / 60;

	//load_avg??? float?????? ??????
	int load_avg_old = load_avg;
	int ready_threads = thread_active  - (int) list_size(&blocked_list);
	load_avg= fp_mul (c1, load_avg_old) + c2 * ready_threads;
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	// recent cpu??? float ??? ??????
	return fp_toint_lound_near (thread_current()->recent_cpu * 100);
}

void
thread_calc_recent_cpu(struct thread* t){
	int tmp = fp_div (2 * load_avg, 2 * load_avg + fp_tofp(1));
	tmp = fp_mul (tmp, t->recent_cpu) + fp_tofp (t->nice);
	t->recent_cpu = tmp;
}


//fixed-point artimetics
//be careful: FP????????? ????????? ???!
// add, sub??? ?????? fp/int?????? ????????? ?????? ???
// mul/sub??? fp*/ int??? ?????? ?????? ?????? ??????
# define FP  (1<<14) 
int fp_tofp (int n){
	return n*FP;
}
int fp_toint_lound_zero (int x){
	return x/FP;
}
int fp_toint_lound_near (int x){
	if (x>0){
		return (x + FP / 2) / FP;
	}
	else return (x - FP / 2) / FP;
}
int UNUSED fp_add (int x, int y){
	return x+y;
}
int UNUSED fp_sub (int x, int y){
	return x-y;
}
int fp_mul (int x, int y){
	return ((int64_t) x) * y /FP;
}
int fp_div (int x, int y){	
	return ((int64_t) x) * FP/ y;
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);


	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);

	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->blocking_lock = NULL;
	t->exitcode = 0;
	list_init (&t->acquired_locks);

	t->parent = NULL;

	t->magic = THREAD_MAGIC;
	list_init (&t->open_file);
	t->open_file_cnt = 0;

	//for advanced scheduler
	if (thread_mlfqs){
		t->nice=0;
		t->recent_cpu=0;
		t->priority = PRI_DEFAULT;
		t->block_unblock=0;
	}

	t->current_dir = NULL;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
	{
		// Find highest priority bucket from ready_list
		//  and pop first and remove empty bucket if necessary
		struct priority_bucket* highest_priority_bucket = list_entry (list_front (&ready_list), struct priority_bucket, elem);
		ASSERT (!list_empty (&highest_priority_bucket->bucket));
		struct thread *t = list_entry (list_front (&highest_priority_bucket->bucket), struct thread, elem);
		bucket_remove (t);
		return t;
	}
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

void
bucket_push (struct thread *t) {
	int priority = thread_get_priority_of (t);
	struct priority_bucket* bucket = &priority_buckets[priority];


	if (list_empty (&bucket->bucket))
		// ordered insert ready_list
		list_insert_ordered (&ready_list, &bucket->elem, bucket_pointer_more, NULL);


	list_push_back (&bucket->bucket, &t->elem);

}

void
bucket_remove (struct thread *t) {
	int priority = thread_get_priority_of (t);
	struct priority_bucket* bucket = &priority_buckets[priority];
	list_remove (&t->elem);
	if (list_empty (&bucket->bucket))
		list_remove (&bucket->elem);

}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}

static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;


#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used bye the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back (&destruction_req, &curr->elem);

			thread_active--;
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		thread_launch (next);
	}
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}

static bool
bucket_pointer_more (const struct list_elem *a,

		const struct list_elem *b, void* aux UNUSED) {
	struct priority_bucket* a_pointer = list_entry (a, struct priority_bucket, elem);
	struct priority_bucket* b_pointer = list_entry (b, struct priority_bucket, elem);
	// Decreasing order of array element pointer of buckets
	return a_pointer > b_pointer;
}

static bool
lock_priority_less (const struct list_elem *a, const struct list_elem *b,
		void* aux UNUSED) {
	int a_pri = list_entry (a, struct lock, elem)->max_donated_priority;
	int b_pri = list_entry (b, struct lock, elem)->max_donated_priority;
	return a_pri < b_pri;
}

struct child_info *
new_child_info () {
	struct child_info *cinfo = (struct child_info *) malloc(sizeof(struct child_info));

	cinfo->tid = NULL;
	cinfo->parent_tid = NULL;
	sema_init (&cinfo->sema, 0);
	cinfo->exitcode = NULL;

	list_push_back (&children_info, &cinfo->elem);
	return cinfo;
}

struct child_info *
get_child_info (tid_t child_tid) {
	struct list_elem *i;
	struct child_info *cinfo;

	if (list_empty (&children_info))
		return NULL;

	for (i = list_front (&children_info); i != list_end (&children_info); i = list_next (i))
	{
		cinfo = list_entry (i, struct child_info, elem);
		if (cinfo->tid == child_tid)
			return cinfo;
	}

	return NULL;
}
