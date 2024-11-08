#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

/* Lock used when handling files to ensure synchronisation. */
static struct lock file_lock;

static void syscall_handler (struct intr_frame *);

static bool validate_user_pointer(const void *ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf ("system call number: %d\n", f->esp);

  void *buffer = *(void **)(f->esp + 8);

  if (!validate_user_pointer(f->esp) || !validate_user_pointer(buffer)) {
    // Terminate process since the given pointer (user or stack) is invalid
    sys_exit(-1);
  }

  thread_exit ();
}

/* Terminates PintOS. */
void
sys_halt (void) {
  /* Calls shutdown_power_off() from devices/shutdown.h. */
  shutdown_power_off();
}

/* Terminate this process. */
void 
sys_exit (int status) {
  /* Sets the exit status of the current thread. */
  struct thread *cur = thread_current();
  cur->exit_status = status;

  /* Prints the process termination message. */
  printf ("%s: exit(%d)\n", cur->name, status);

  /* Terminates current thread. */
  thread_exit();
}

/* Writes bytes from buffer to the open file or console */
int 
sys_write (int fd, const void *buffer, unsigned size) {
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

  /* writing to a file only up until EOF*/
  lock_acquire(&file_lock);
  struct o_file *opened_file = get_o_file_from_fd(fd);

  /* Checks if file is NULL. */
  if (opened_file == NULL) {
    return 0;
  }

  /* writes to file from current offset and return amount written */
  off_t file_offset = file_tell(opened_file->file);
  rem_size = file_write_at (opened_file->file, buffer, size, file_offset);
  lock_release(&file_lock);
  return rem_size;
}

/* Creates a new file with the given name and initial size. */
bool 
sys_create (const char *file, unsigned initial_size) {
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

/* Removes the file with the given name. */
bool 
sys_remove (const char *file) {
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

/* Opens the file with the given name. */
int 
sys_open (const char *file) {

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
int 
sys_filesize (int fd) {
  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls file_length() from filesys/file.c. */
  struct o_file *opened_file = get_o_file_from_fd(fd);

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

/* Reads size bytes from the file open as fd into buffer. */
int 
sys_read (int fd, void *buffer, unsigned size) {
  /* Checks if buffer is valid. */
  if (!is_user_vaddr(buffer) || buffer == NULL) {
    sys_exit(-1);
  }

  if (fd == STDOUT_FILENO) {
    /* Cannot read from stdout. */
    return -1;
  } else if (fd == STDIN_FILENO) {
    /* Read from the keyboard into the buffer. */
    unsigned i;
    for (i = 0; i < size; i++) {
        ((uint8_t *) buffer)[i] = input_getc();
    }

    return size; 
  } else {
    struct o_file *opened_file = get_o_file_from_fd(fd);
    
    if (opened_file == NULL || opened_file->file == NULL) {
      return -1;
    }

    // Read from the file into the buffer, returning the bytes written.
    return file_read(opened_file->file, buffer, size);
  }
}

/* Changes the next byte to be read or written in open file fd to position. */
void 
sys_seek (int fd, unsigned position) {
  /* Acquires opened file from fd. */
    struct o_file *open_file = get_o_file_from_fd(fd);
    if (open_file != NULL) {
      /* If descriptor not null use file_seek(file, position). */
        file_seek (open_file->file, position);
    }
}

/* Returns the position of the next byte to be read or written in open file fd. */
unsigned 
sys_tell (int fd) {
  /* Acquires opened file from fd. */
    struct o_file *open_file = get_o_file_from_fd(fd);
    if (open_file != NULL) {
      /* If descriptor not null use file_tell(file). */
        return file_tell (open_file->file);
    }
    return -1;
}

/* Closes file descriptor fd. */
void 
sys_close (int fd) {
    struct o_file *open_file = get_o_file_from_fd(fd);

    // If the file is found, close it
    if (open_file != NULL) {
        file_close (open_file->file);

        // Remove the entry from the open_files hash table.
        hash_delete (&thread_current()->file_descriptors, &open_file->fd_elem);

        free(open_file);
    }
}

/*  Take in a user pointer and check that it is valid, i.e:
  1. Is not NULL
  2. Points to unmapped virtual memory
  3. Points to kernel address space
*/
static bool
validate_user_pointer(const void *uaddr) {

  if (uaddr == NULL) {
    return false;
  }

  if (!is_user_vaddr(uaddr)) {
    return false;
  }

  if (pagedir_get_page(thread_current()->pagedir, uaddr) == NULL) {
    return false;
  }

  return true;
}
