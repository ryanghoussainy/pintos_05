#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
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

/* Array of function pointers to handle syscalls. */
syscall_func_t syscall_table[NUM_SYSCALLS];

static void init_syscalls_table(void);
static void syscall_handler (struct intr_frame *);

/* Syscall functions */
static void sys_halt (struct intr_frame *f);
static void sys_exit (struct intr_frame *f);
static void sys_write (struct intr_frame *f);
static void sys_exec (struct intr_frame *f);
static void sys_wait (struct intr_frame *f);
static void sys_create (struct intr_frame *f);
static void sys_remove (struct intr_frame *f);
static void sys_open (struct intr_frame *f);
static void sys_filesize (struct intr_frame *f);
static void sys_read (struct intr_frame *f);
static void sys_write (struct intr_frame *f);
static void sys_seek (struct intr_frame *f);
static void sys_tell (struct intr_frame *f);
static void sys_close (struct intr_frame *f);

static bool validate_user_pointer(const void *ptr);
static uint32_t load_number_from_vaddr (void *vaddr);
static char *load_address_from_vaddr (void *vaddr);
static bool is_valid_user_address_range(const void *start, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Initialise the syscall table and file system lock. */
  init_syscalls_table();
  lock_init(&filesys_lock);
}

/* Initialising function pointer table for handling syscalls. */
static void
init_syscalls_table(void) 
{
  syscall_table[SYS_HALT] = sys_halt;
  syscall_table[SYS_EXIT] = sys_exit;
  syscall_table[SYS_EXEC] = sys_exec;
  syscall_table[SYS_WAIT] = sys_wait;
  syscall_table[SYS_CREATE] = sys_create;
  syscall_table[SYS_REMOVE] = sys_remove;
  syscall_table[SYS_OPEN] = sys_open;
  syscall_table[SYS_FILESIZE] = sys_filesize;
  syscall_table[SYS_READ] = sys_read;
  syscall_table[SYS_WRITE] = sys_write;
  syscall_table[SYS_SEEK] = sys_seek;
  syscall_table[SYS_TELL] = sys_tell;
  syscall_table[SYS_CLOSE] = sys_close;
}

static void
syscall_handler (struct intr_frame *f) 
{

  if (!validate_user_pointer(get_arg_1(f->esp)) || 
      !validate_user_pointer(get_arg_2(f->esp)) ||
      !validate_user_pointer(get_arg_3(f->esp))) 
  {
    /* Terminate process since the given pointer (user or stack) is invalid */
    exit(-1);
    return;
  }

  /* Load the syscall number from the stack. */
  int syscall_num = load_number_from_vaddr(f->esp);

  /* Ensure that the syscall number is valid. */
  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) 
  {
    exit(-1);
    return;
  }

  /* Call the appropriate syscall function. */
  syscall_func_t syscall = syscall_table[syscall_num];
  syscall(f);
}

/* Terminates PintOS. */
static void
sys_halt (struct intr_frame *f UNUSED)  
{
  /* Calls shutdown_power_off() from devices/shutdown.h. */
  shutdown_power_off();
}

/* Terminate this process. */
static void 
sys_exit (struct intr_frame *f) 
{
  /* Loads the exit status from the stack. */
  int status = load_number_from_vaddr(get_arg_1(f->esp));
  exit(status);
}

/* Runs the executable whose name is given in cmd line, passing any given 
arguments, and returns the new process’s program id (pid).*/
static void
sys_exec(struct intr_frame *f)
{
  /* Load the command line from the stack. */
  const char *cmd_line = load_address_from_vaddr(get_arg_1(f->esp));

  /* Return -1 if cmd_line is not valid */
  if (!validate_user_pointer(cmd_line)) {
    f->eax = -1;
    exit(-1);
    return;
  }
  f->eax = process_execute(cmd_line); 
}

/* Waits for a child process pid and retrieves the child's exit status. */
static void
sys_wait(struct intr_frame *f)
{
  /* Load the pid from the stack. */
  pid_t pid = load_number_from_vaddr(get_arg_1(f->esp));
  f->eax = process_wait(pid);
}

/* Writes bytes from buffer to the open file or console */
static void 
sys_write (struct intr_frame *f) 
{
  /* Loads the file descriptor, buffer and size from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));
  const void *buffer = load_address_from_vaddr(get_arg_2(f->esp));
  unsigned size = load_number_from_vaddr(get_arg_3(f->esp));

  /* Checks if buffer is valid. */
  if (!is_valid_user_address_range(buffer, size)) {
    exit(-1);
    return;
  }

  /* Writing to console and splitting buffer into defined chunks if needed */
  int rem_size;
  if (fd == STDOUT_FILENO){
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
    f->eax = size;
    return;
  }

  /* Writing to a file only up until EOF. */
  lock_acquire(&filesys_lock);
  struct o_file *opened_file = get_o_file_from_fd(fd);

  /* Checks if file is NULL. */
  if (opened_file == NULL) {
    lock_release(&filesys_lock);
    exit(-1);
    return;
  }

  /* Writes to file from current offset and return amount written. */
  rem_size = file_write (opened_file->file, buffer, size);
  lock_release(&filesys_lock);
  f->eax = rem_size;
}

/* Creates a new file with the given name and initial size. */
static void 
sys_create (struct intr_frame *f) 
{
  /* Loads the file name and initial size from the stack. */
  const char *file = load_address_from_vaddr(get_arg_1(f->esp));
  unsigned initial_size = *(unsigned *) (get_arg_2(f->esp));

  /* Checks if file is NULL. */
  if (file == NULL || !validate_user_pointer(file)) {
    f->eax = false;
    exit(-1);
    return;
  }


  /* Create the file */
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  f->eax = success;
}

/* Removes the file with the given name. */
static void 
sys_remove (struct intr_frame *f) 
{
  /* Loads the file name from the stack. */
  const char *file = load_address_from_vaddr(get_arg_1(f->esp));

  /* Checks if file is NULL. */
  if (file == NULL) 
  {
    f->eax = false;
    return;
  }


  /* Remove the file */
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  f->eax = success;
}

/* Opens the file with the given name. */
static void 
sys_open (struct intr_frame *f) 
{
  /* Loads the file name from the stack. */
  const char *file = load_address_from_vaddr(get_arg_1(f->esp));

  /* Checks if file is NULL. */
  if (file == NULL || !validate_user_pointer(file)) 
  {
    f->eax = -1;
    exit(-1);
    return;
  }

  /* Opens the file */
  lock_acquire(&filesys_lock);
  struct file *new_file = filesys_open(file);
  if (new_file == NULL) 
  {
    lock_release(&filesys_lock);
    f->eax = -1;
    return;
  }

  /* Creates an opened file struct. */
  struct o_file *cur_o_file = malloc(sizeof(struct o_file));
  if (cur_o_file == NULL) 
  {
    file_close(new_file);
    lock_release(&filesys_lock);
    f->eax = -1;
    return;
  }

  /* Sets the file descriptor and file. */
  struct thread *cur = thread_current();
  cur_o_file->fd = cur->next_fd++;
  cur_o_file->file = new_file;

  /* If the file descriptor is greater than the maximum number of files, return -1. */
  if (cur_o_file->fd >= MAX_OFILES) 
  {
    file_close(new_file);
    free(cur_o_file);
    lock_release(&filesys_lock);
    f->eax = -1;
    return;
  }

  /* Inserts the file descriptor into the hash table of running process. */
  hash_insert(&cur->file_descriptors, &cur_o_file->fd_elem);

  lock_release(&filesys_lock);
  f->eax = cur_o_file->fd;
}

/* Returns the length, in bytes, of the file open as fd. */
static void 
sys_filesize (struct intr_frame *f) 
{
  /* Loads the file descriptor from the stack. */
  int fd = *(int *) (get_arg_1(f->esp));

  /* Acquires opened file from fd. */
  lock_acquire(&filesys_lock);
  struct o_file *opened_file = get_o_file_from_fd(fd);
  if (opened_file == NULL) {
    lock_release(&filesys_lock);
    f->eax = -1;
    return;
  }

  /* Get the length of the file. */
  int length = file_length(opened_file->file);
  lock_release(&filesys_lock);
  f->eax = length;
}

/* Reads size bytes from the file open as fd into buffer. */
static void 
sys_read (struct intr_frame *f) 
{
  /* Loads the file descriptor, buffer and size from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));
  void *buffer = load_address_from_vaddr(get_arg_2(f->esp));
  unsigned size = load_number_from_vaddr(get_arg_3(f->esp));

  /* Checks if buffer is valid. */
  if (!is_valid_user_address_range(buffer, size)) {
    exit(-1);
    return;
  }

  /* Check if the file descriptor is valid. */
  if (fd == STDOUT_FILENO) {
    /* Cannot read from stdout. */
    f->eax = -1;
    return;
  } else if (fd == STDIN_FILENO) {
    /* Read from the keyboard into the buffer. */
    unsigned i;
    uint8_t *new_buff = (uint8_t *) buffer;
    for (i = 0; i < size; i++) {
        new_buff[i] = input_getc();
    }
    f->eax = size;
    return; 
  } else {
    /* Get the opened file from the file descriptor. */
    lock_acquire(&filesys_lock);
    struct o_file *opened_file = get_o_file_from_fd(fd);
    if (opened_file == NULL) {
      lock_release(&filesys_lock);
      f->eax = -1;
      return;
    }

    /* Read from the file into the buffer, returning the bytes written. */
    int read_characters = file_read(opened_file->file, buffer, size);
    lock_release(&filesys_lock);
    f->eax = read_characters;
  }
}

/* Changes the next byte to be read or written in open file fd to position. */
static void 
sys_seek (struct intr_frame *f) 
{
  /* Loads the file descriptor and position from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));
  unsigned position = load_number_from_vaddr(get_arg_2(f->esp));

  /* Acquires opened file from fd. */
  lock_acquire(&filesys_lock);
  struct o_file *open_file = get_o_file_from_fd(fd);
  if (open_file == NULL) {
    lock_release(&filesys_lock);
    return;
  }

  /* Seek to the position in the file. */
  file_seek (open_file->file, position);
  lock_release(&filesys_lock);
}

/* Returns the position of the next byte to be read or written in open file fd. */
static void 
sys_tell (struct intr_frame *f) 
{
  /* Loads the file descriptor from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));

  /* Acquires opened file from fd. */
  lock_acquire(&filesys_lock);
  struct o_file *open_file = get_o_file_from_fd(fd);
  if (open_file == NULL) {
    lock_release(&filesys_lock);
    f->eax = 0;
    return;
  }
  
  /* Get the position of the file. */
  int position = file_tell(open_file->file);
  lock_release(&filesys_lock);
  f->eax = position;
}

/* Closes file descriptor fd. */
static void 
sys_close (struct intr_frame *f) 
{
  /* Loads the file descriptor from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));

  /* Get the opened file from the file descriptor. */
  lock_acquire(&filesys_lock);
  struct o_file *open_file = get_o_file_from_fd(fd);
  if (open_file == NULL) {
    lock_release(&filesys_lock);
    return;
  }

  /* Close the file */
  file_close (open_file->file);

  /* Remove the entry from the open_files hash table. */
  hash_delete (&thread_current()->file_descriptors, &open_file->fd_elem);

  /* Free the opened file struct */
  free(open_file);
  lock_release(&filesys_lock);
}

/*  Take in a user pointer and check that it is valid, i.e:
  1. Is not NULL
  2. Points to unmapped virtual memory
  3. Points to kernel address space
*/
static bool
validate_user_pointer(const void *uaddr) 
{
  return (uaddr != NULL 
          && is_user_vaddr(uaddr) 
          && pagedir_get_page(thread_current()->pagedir, uaddr) != NULL);
}

/* Deferences stack pointer into an uint32_t. */
static uint32_t load_number_from_vaddr (void *vaddr)
{
	return *((uint32_t *) vaddr);
}

/* Deferences stack pointer into a pointer to a char. */
static char *load_address_from_vaddr (void *vaddr)
{
	return *((char **) vaddr);
}

void
exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;
  thread_exit();
}

/* Checks if the given address range is valid. */
static bool is_valid_user_address_range(const void *start, unsigned size) {
  const uint8_t *addr = (const uint8_t *)start;
  for (unsigned i = 0; i < size; i++) {
    if (!is_user_vaddr(addr) || pagedir_get_page(thread_current()->pagedir, addr) == NULL) {
      return false;
    }
    addr++;
  }
  return true;
}
