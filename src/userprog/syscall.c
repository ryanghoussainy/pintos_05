#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"

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

/* Writes bytes from buffer to the open file or console */
int sys_write (int fd, const void *buffer, unsigned size) {
  /* Writing to console and splitting buffer into defined chunks if needed */
  int rem_size;
  if (fd == 1){
    int rem_size = size;
    while (rem_size > 0) {
      /* writes predefined amount to console or just
         the remaining size if less */
      if (rem_size < CONSOLE_INCR) {
        putbuf(buffer, rem_size);
        rem_size = 0;
      } else {
        putbuf(buffer, CONSOLE_INCR);
        rem_size -= CONSOLE_INCR;
      }
    }
    return size;
  }

  /* writing to a file only up until EOF, by calculating remaining space */
  int file_size = file_length(fd);
  off_t file_offset = file_tell(fd);
  rem_size = file_size - file_offset;
  file_write (fd, buffer, rem_size);
  return rem_size;
}
