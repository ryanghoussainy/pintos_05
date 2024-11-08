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
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#ifdef USERPROG
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "lib/kernel/hash.h"
#endif


/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;

/* Load average for the system */
static int32_t load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);
static void thread_set_priority_for_thread(struct thread *t, int new_priority);
static bool thread_less(const struct list_elem *a_,
                        const struct list_elem *b_,
                        void *aux UNUSED);
static void thread_calculate_priority(struct thread *t, void *aux UNUSED);

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
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Returns the number of threads currently in the ready list. 
   Disables interrupts to avoid any race-conditions on the ready list. */
size_t
threads_ready (void)
{
  enum intr_level old_level = intr_disable ();
  size_t ready_thread_count = list_size (&ready_list);
  intr_set_level (old_level);
  return ready_thread_count;
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs)
  {
    /* Update recent_cpu for the current thread if thread is not idle. */
    if (t != idle_thread) 
    {
      t->recent_cpu = add_fixed_point_to_integer(t->recent_cpu, 1);
    }

    /* Update load_avg and recent_cpu for all threads every second. */
    if (timer_ticks() % TIMER_FREQ == 0)
    {
      thread_calculate_load_avg();
      thread_foreach(&thread_recalculate_recent_cpu, NULL);
    }

    /* Update priority for all threads every fourth tick. */
    if (timer_ticks() % TIME_SLICE == 0)
    {
      thread_foreach(&thread_calculate_priority, NULL);
    }
  }

  /* Enforce preemption */
  if (!list_empty(&ready_list)) {
    struct thread *max_priority_ready_thread = list_entry(list_front(&ready_list), struct thread, elem);
    if (thread_get_effective_priority(max_priority_ready_thread) > thread_get_priority()) {
      intr_yield_on_return();
    }
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
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
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* The parent will be the thread running when thread_create() is called */
  struct thread *t_parent = thread_current ();

  t->nice = t_parent->nice;
  t->recent_cpu = 0;

  if (thread_mlfqs)
  {
    thread_calculate_priority(t, NULL);
  }
  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

  /* If the new thread has a higher priority than the current thread, yield. */
  if (t->priority > thread_get_priority()) {
    thread_yield();
  }

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
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
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered (&ready_list, &t->elem, thread_more, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
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
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) {
    list_insert_ordered (&ready_list, &cur->elem, thread_more, NULL);
  }
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  thread_set_priority_for_thread(thread_current(), new_priority);
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_get_effective_priority(thread_current());
}

/* Returns the effective priority of the thread t. */
int
thread_get_effective_priority(struct thread *t)
{
  int out = t->priority;

  if (thread_mlfqs)
  {
    return out;
  }

  enum intr_level old_level = intr_disable();

  /* Donations:
     For each lock that T holds, we will consider every waiting thread with a higher
     priority than T's a donor. */
  struct list_elem *e;
  for (e = list_begin(&t->locks); e != list_end(&t->locks); e = list_next(e))
  {
    struct lock *lock = list_entry(e, struct lock, elem);

    if (!list_empty(&lock->semaphore.waiters))
    {
      struct thread *waiter = list_entry(list_max(&lock->semaphore.waiters, thread_less, NULL),
                                         struct thread,
                                         elem);
      
      int waiter_priority = thread_get_effective_priority(waiter);
      if (waiter_priority > out)
      {
        out = waiter_priority;
      }
    }
  }

  intr_set_level(old_level);

  return out;
}

/* Calculates the priority of a thread in the advanced scheduler. */
void 
thread_calculate_priority(struct thread *t, void *aux UNUSED)
{
  ASSERT (thread_mlfqs);
  
  /* Calculate priority*/
  int maxPriority_fp = convert_to_fixed_point(PRI_MAX);
  int recent_cpu = div_fixed_point_by_integer(t->recent_cpu, 4);
  int nice_fp = convert_to_fixed_point(t->nice);
  int calculated_priority = sub_fixed_point(maxPriority_fp, recent_cpu);
  calculated_priority = sub_fixed_point(calculated_priority, mul_fixed_point_by_integer(nice_fp, 2));
  calculated_priority = convert_to_integer_zero(calculated_priority);
  
  /* Adjust calculated priority to lie in the valid range PRI_MIN to PRI_MAX */
  calculated_priority = MAX(PRI_MIN, calculated_priority);
  calculated_priority = MIN(PRI_MAX, calculated_priority);

  /* Set thread's priority to calculated priority */
  thread_set_priority_for_thread(t, calculated_priority);
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  ASSERT (thread_mlfqs);
  struct thread *cur = thread_current();
  
  cur->nice = nice;
  
  thread_calculate_priority(cur, NULL);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  ASSERT (thread_mlfqs);
  struct thread *cur = thread_current();
  return cur->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return convert_to_integer_nearest(mul_fixed_point_by_integer(load_avg, 100));
}

/* Calculates the load_avg, the average number of threads ready to run over the past minute. */
void
thread_calculate_load_avg(void)
{
  int load_avg_frac = div_fixed_point_by_integer(convert_to_fixed_point(59), 60);
  int ready_threads_frac = div_fixed_point_by_integer(convert_to_fixed_point(1), 60);

  enum intr_level old_level = intr_disable();
  int ready_threads = list_size (&ready_list);
  intr_set_level(old_level);

  if (thread_current() != idle_thread)
  {
    ready_threads++;
  }

  load_avg = add_fixed_point(mul_fixed_point(load_avg_frac, load_avg), 
                             mul_fixed_point_by_integer(ready_threads_frac, ready_threads));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  struct thread *cur = thread_current ();
  int fp_cur_recent_cpu = cur->recent_cpu;
  return convert_to_integer_nearest(fp_cur_recent_cpu) * 100;
}

/* Recalculates the recent_cpu value of the specified thread. */
void
thread_recalculate_recent_cpu (struct thread *t, void *aux UNUSED)
{
  int ans_fp_numerator = mul_fixed_point_by_integer(load_avg, 2);
  int ans_fp_denominator = add_fixed_point_to_integer(mul_fixed_point_by_integer(load_avg, 2), 1);
  int ans_fp = add_fixed_point_to_integer(
    mul_fixed_point(
      div_fixed_point(ans_fp_numerator, ans_fp_denominator), t->recent_cpu),
      t->nice);
  t->recent_cpu = ans_fp;
}

/* Sorts the ready list in descending order of priority. */
void
sort_ready_list(void)
{
  list_sort(&ready_list, thread_more, NULL);
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
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
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
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  list_init(&t->locks);

#ifdef USERPROG
  list_init(&t->files);
  t->file_descriptors = malloc(sizeof(struct hash));
  hash_init(t->file_descriptors, fd_hash, fd_less, NULL);
  /* assertion until malloc failure is handled properly */
  ASSERT (file_descriptors != NULL);
  t->next_fd = 2;
#endif

  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list)) {
    return idle_thread;
  } else {
    struct list_elem *e = list_pop_front(&ready_list);
    struct thread *t = list_entry(e, struct thread, elem);
    return t;
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/* Sets the thread T's priority to NEW_PRIORITY */
static void
thread_set_priority_for_thread(struct thread *t, int new_priority)
{
  enum intr_level old_level = intr_disable();

  int old_priority = t->priority;
  t->priority = new_priority;

  sort_ready_list();

  if (new_priority < old_priority) {
    /* If the new priority is lower than the old priority, and there is a thread with
      a higher priority, yield. */
    if (!list_empty(&ready_list)) {
      struct thread *max_priority_ready_thread = list_entry(list_front(&ready_list), struct thread, elem);
      if (thread_get_effective_priority(max_priority_ready_thread) > thread_get_priority()) {
        if (intr_context()) {
          intr_yield_on_return();
        } else {
          thread_yield();
        }
      }
    }
  }

  intr_set_level(old_level);
}

/* Returns true if priority of a is greater than priority of b. */
bool
thread_more(const struct list_elem *a_,
                        const struct list_elem *b_,
                        void *aux UNUSED)
{
  struct thread *thread_a = list_entry (a_, struct thread, elem);
  struct thread *thread_b = list_entry (b_, struct thread, elem);

  return thread_get_effective_priority(thread_a) > thread_get_effective_priority(thread_b);
}

/* Returns true if priority of a is less than priority of b. */
static bool
thread_less(const struct list_elem *a_,
            const struct list_elem *b_,
            void *aux UNUSED)
{
  struct thread *thread_a = list_entry (a_, struct thread, elem);
  struct thread *thread_b = list_entry (b_, struct thread, elem);

  return thread_get_effective_priority(thread_a) < thread_get_effective_priority(thread_b);
}

#ifdef USERPROG
/* Hash function for file descriptors, using the fd number */
unsigned fd_hash(const struct hash_elem *e, void *aux UNUSED) {
  const struct o_file *fd_struct = hash_entry(e, struct o_file, fd_elem);
  return hash_int(fd_struct->fd);
}

/* Comparison function for file descriptors */
bool fd_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct o_file *fd_a = hash_entry(a, struct o_file, fd_elem);
  const struct o_file *fd_b = hash_entry(b, struct o_file, fd_elem);
  return fd_a->fd < fd_b->fd;
}
#endif
