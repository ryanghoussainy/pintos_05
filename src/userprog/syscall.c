#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include <stdlib.h> 

/* Lock used when handling files to ensure synchronisation. */
static struct lock file_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call number: %d\n", f->esp);
  thread_exit ();
}

/* Terminates PintOS. */
void sys_halt (void) {
  /* Calls shutdown_power_off() from devices/shutdown.h. */
  shutdown_power_off();
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

/* Creates a new file with the given name and initial size. */
bool sys_create (const char *file, unsigned initial_size) {
  /* Checks if file is NULL. */
  if (file == NULL) {
    sys_exit(-1);
  }

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls filesys_create() from filesys/filesys.c. */
  bool success = filesys_create(file, initial_size);

  /* Releases file lock. */
  lock_release(&file_lock);

  /* Returns if operation was successful or not. */
  return success;
}

bool sys_remove (const char *file) {
  /* Checks if file is NULL. */
  if (file == NULL) 
  {
    sys_exit(-1);
  }

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls filesys_remove() from filesys/filesys.c. */
  bool success = filesys_remove(file);

  /* Releases file lock. */
  lock_release(&file_lock);

  /* Returns if operation was successful or not. */
  return success;
}

int sys_open (const char *file) {

  /* Checks if file is NULL. */
  if (file == NULL) 
  {
    return -1;
  }

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls filesys_open() from filesys/filesys.c. */
  struct file *f = filesys_open(file);

  /* Checks if file is NULL. */
  if (f == NULL) 
  {
    return -1;
  }

  /* Creates an opened file struct. */
  struct o_file *cur_o_file = malloc(sizeof(struct o_file));

  /* Allocate memory for struct o_file. */
  if (cur_o_file == NULL) 
  {
    
    file_close(f);
    return -1;
  }
  /* Sets the file descriptor and file. */
  struct thread *cur = thread_current();
  cur_o_file->fd = cur->next_fd++;
  cur_o_file->file = f;

  /* Inserts the file descriptor into the hash table of running process. */
  hash_insert(&cur->file_descriptors, &cur_o_file->fd_elem);

  /* Releases file lock. */
  lock_release(&file_lock);

  /* Returns the file descriptor. */
  return cur_o_file->fd;
}

/* Returns the length, in bytes, of the file open as fd. */
int sys_filesize (int fd) {
  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls file_length() from filesys/file.c. */
  struct o_file *opened_file = process_get_open_file_struct(fd);

  /* Checks if file is NULL. */
  if (opened_file == NULL) {
    return -1;
  }
  int length = file_length(opened_file->file);

  /* Releases file lock. */
  lock_release(&file_lock);

  /* Returns the length of the file. */
  return length;
}

struct o_file *
process_get_open_file_struct(int fd) {
    /* Check if input fd is valid. */
    if (fd < 2) {
        return NULL;
    }

    struct thread *cur = thread_current();

    /* Get the corresponding opened file from the hash map. */
    struct o_file search_open_file;
    search_open_file.fd = fd;

    /* Find file in fd hash table. */
    struct hash_elem *found_file_elem = hash_find(&cur->file_descriptors, &search_open_file.fd_elem);

    // File not found, return NULL.
    if (found_file_elem == NULL) {
        return NULL;
    }

    // Else, return the file.
    struct o_file *open_file = hash_entry(found_file_elem, struct o_file, fd_elem);
  
    return open_file;
}
