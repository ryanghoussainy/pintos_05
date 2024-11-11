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

static void exit(int status);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Initialise the syscall table and file lock. */
  init_syscalls_table();
  lock_init(&file_lock);
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
    // Terminate process since the given pointer (user or stack) is invalid
    exit(-1);
    return;
  }

  int syscall_num = load_number_from_vaddr(f->esp);

  /* Ensure that the syscall number is valid. */
  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) 
  {
    exit(-1);
    return;
  }

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
  }

  tid_t child_tid = process_execute(cmd_line);

  if (child_tid == TID_ERROR) {
    f->eax = -1;
  }

  struct thread *child = get_thread_by_tid(child_tid);
  ASSERT(child != NULL);

  // Wait for the child to load
  sema_down(&child->pLink->sema);

  // If the child failed to load, return -1
  if (child->pLink->load_status == LOAD_FAILED) {
    f->eax = -1;
  }
  f->eax = child_tid;
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
  lock_acquire(&file_lock);
  struct o_file *opened_file = get_o_file_from_fd(fd);

  /* Checks if file is NULL. */
  if (opened_file == NULL) {
    lock_release(&file_lock);
    f->eax = 0;
    return;
  }

  /* Writes to file from current offset and return amount written. */
  off_t file_offset = file_tell(opened_file->file);
  rem_size = file_write_at (opened_file->file, buffer, size, file_offset);
  lock_release(&file_lock);
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
  if (file == NULL) {
    f->eax = false;

    // Terminate process since the syscall number is invalid
    exit(-1);
    return;
  }

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls filesys_create() from filesys/filesys.c. */
  bool success = filesys_create(file, initial_size);

  /* Releases file lock. */
  lock_release(&file_lock);
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

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls filesys_remove() from filesys/filesys.c. */
  bool success = filesys_remove(file);

  /* Releases file lock. */
  lock_release(&file_lock);
  f->eax = success;
}

/* Opens the file with the given name. */
static void 
sys_open (struct intr_frame *f) 
{
  /* Loads the file name from the stack. */
  const char *file = load_address_from_vaddr(get_arg_1(f->esp));

  /* Checks if file is NULL. */
  if (file == NULL) 
  {
    f->eax = -1;  
    return;
  }

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Calls filesys_open() from filesys/filesys.c. */
  struct file *new_file = filesys_open(file);

  /* Checks if file is NULL. */
  if (new_file == NULL) 
  {
    lock_release(&file_lock);
    f->eax = -1;
    return;
  }

  /* Creates an opened file struct. */
  struct o_file *cur_o_file = malloc(sizeof(struct o_file));

  /* Check if opened file is NULL. */
  if (cur_o_file == NULL) 
  {
    file_close(new_file);
    lock_release(&file_lock);
    f->eax = -1;
    return;
  }

  /* Sets the file descriptor and file. */
  struct thread *cur = thread_current();
  cur_o_file->fd = cur->next_fd++;
  cur_o_file->file = new_file;

  /* Inserts the file descriptor into the hash table of running process. */
  hash_insert(cur->file_descriptors, &cur_o_file->fd_elem);

  /* Releases file lock. */
  lock_release(&file_lock);
  f->eax = cur_o_file->fd;
}

/* Returns the length, in bytes, of the file open as fd. */
static void 
sys_filesize (struct intr_frame *f) 
{
  /* Loads the file descriptor from the stack. */
  int fd = *(int *) (get_arg_1(f->esp));

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Acquires opened file from fd. */
  struct o_file *opened_file = get_o_file_from_fd(fd);

  /* Checks if opened file is NULL. */
  if (opened_file == NULL) {
    lock_release(&file_lock);
    f->eax = -1;
    return;
  }
  /* Calls file_length() from filesys/file.c. */
  int length = file_length(opened_file->file);

  /* Releases file lock. */
  lock_release(&file_lock);
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
  if (!is_user_vaddr(buffer) || buffer == NULL) {
    process_exit();
  }

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
    /* Acquire the file lock to ensure synchronisation. */
    lock_acquire(&file_lock);

    /* Get the opened file from the file descriptor. */
    struct o_file *opened_file = get_o_file_from_fd(fd);
    
    /* Check if the file is NULL. */
    if (opened_file == NULL) {
      lock_release(&file_lock);
      f->eax = -1;
      return;
    }

    // Read from the file into the buffer, returning the bytes written.
    int read_characters = file_read(opened_file->file, buffer, size);

    /* Release the file lock. */
    lock_release(&file_lock);
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

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Acquires opened file from fd. */
  struct o_file *open_file = get_o_file_from_fd(fd);

  /* Checks if opened file is NULL. */
  if (open_file == NULL) {
    return;
  }

  /* Calls file_seek() from filesys/file.c. */
  file_seek (open_file->file, position);

  /* Release the file lock. */
  lock_release(&file_lock);
}

/* Returns the position of the next byte to be read or written in open file fd. */
static void 
sys_tell (struct intr_frame *f) 
{
  /* Loads the file descriptor from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);

  /* Acquires opened file from fd. */
  struct o_file *open_file = get_o_file_from_fd(fd);

  /* Checks if opened file is NULL. */
  if (open_file == NULL) {
    lock_release(&file_lock);
    f->eax = 0;
    return;
  }
  
  /* Calls file_tell() from filesys/file.c. */
  int position = file_tell(open_file->file);

  /* Releases file lock. */
  lock_release(&file_lock);
  f->eax = position;

}

/* Closes file descriptor fd. */
static void 
sys_close (struct intr_frame *f) 
{
  /* Loads the file descriptor from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));

  /* Acquires file lock to ensure synchronisation. */
  lock_acquire(&file_lock);


  /* Get the opened file from the file descriptor. */
  struct o_file *open_file = get_o_file_from_fd(fd);

  /* Checks if opened file is NULL. */
  if (open_file == NULL) {
      return;
  }

  /* Calls file_close() from filesys/file.c. */
  file_close (open_file->file);

  // Remove the entry from the open_files hash table.
  hash_delete (thread_current()->file_descriptors, &open_file->fd_elem);

  free(open_file);

  /* Releases file lock. */
  lock_release(&file_lock);
}

/*  Take in a user pointer and check that it is valid, i.e:
  1. Is not NULL
  2. Points to unmapped virtual memory
  3. Points to kernel address space
*/
static bool
validate_user_pointer(const void *uaddr) 
{

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

/* Deferences stack pointer into an uint32_t. */
static uint32_t load_number_from_vaddr (void *vaddr)
{
	// if (get_user ((uint8_t *) vaddr) == -1)
	// 	process_exit ();

	return *((uint32_t *) vaddr);
}

/* Deferences stack pointer into a pointer to a char. */
static char *load_address_from_vaddr (void *vaddr)
{
	// if (get_user ((uint8_t *) vaddr) == -1)
	// 	process_exit ();

	return *((char **) vaddr);
}

static void
exit(int status)
{
  struct thread *cur = thread_current();
  cur->exit_status = status;

  printf ("%s: exit(%d)\n", cur->name, status);

  thread_exit();
}
