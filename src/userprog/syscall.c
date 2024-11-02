#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call number: %d\n", f->esp);
  thread_exit ();
}

/* Terminate this process. */
void sys_exit (int status) {
  /* Sets the exit status of the current thread. */
  struct thread *cur = thread_current();
  cur->exit_status = status;

  /* Prints the process termination message. */
  printf ("%s: exit(%d)\n", cur->name, status);

  /* Terminates current thread. */
  thread_exit();
}
