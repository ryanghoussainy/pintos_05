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
#include "vm/page.h"
#include "vm/frame.h"

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
static void sys_mmap (struct intr_frame *f);
static void sys_munmap (struct intr_frame *f);

static struct mapid_file *get_mmap_file_from_mapid(int mapid);
static bool validate_user_pointer(const void *ptr);
static uint32_t load_number_from_vaddr (void *vaddr);
static char *load_address_from_vaddr (void *vaddr);
static bool is_valid_user_address_range(const void *start, unsigned size);
static bool check_any_mapped(void *start, void *stop);

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
  syscall_table[SYS_MMAP] = sys_mmap;
  syscall_table[SYS_MUNMAP] = sys_munmap;
}

static void
syscall_handler (struct intr_frame *f) 
{

  if (!validate_user_pointer(get_arg_1(f->esp)) || 
      !validate_user_pointer(get_arg_2(f->esp)) ||
      !validate_user_pointer(get_arg_3(f->esp))) 
  {
    /* Terminate process since the given pointer (user or stack) is invalid */
    exit(STATUS_ERR);
    return;
  }

  /* Load the syscall number from the stack. */
  int syscall_num = load_number_from_vaddr(f->esp);

  /* Ensure that the syscall number is valid. */
  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) 
  {
    exit(STATUS_ERR);
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

  /* Exit if cmd_line is not valid */
  if (!validate_user_pointer(cmd_line)) {
    f->eax = RETURN_ERR;
    exit(STATUS_ERR);
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
    exit(STATUS_ERR);
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
    exit(STATUS_ERR);
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
    exit(STATUS_ERR);
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
    f->eax = RETURN_ERR;
    exit(STATUS_ERR);
    return;
  }

  /* Opens the file */
  lock_acquire(&filesys_lock);
  struct file *new_file = filesys_open(file);
  if (new_file == NULL) 
  {
    lock_release(&filesys_lock);
    f->eax = RETURN_ERR;
    return;
  }

  /* Creates an opened file struct. */
  struct o_file *cur_o_file = malloc(sizeof(struct o_file));
  if (cur_o_file == NULL) 
  {
    file_close(new_file);
    lock_release(&filesys_lock);
    f->eax = RETURN_ERR;
    return;
  }

  /* Sets the file descriptor and file. */
  struct thread *cur = thread_current();
  cur_o_file->fd = cur->next_fd++;
  cur_o_file->file = new_file;

  /* Exit if the file descriptor is greater than the maximum number of files */
  if (cur_o_file->fd >= MAX_OFILES) 
  {
    file_close(new_file);
    free(cur_o_file);
    lock_release(&filesys_lock);
    f->eax = RETURN_ERR;
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
    f->eax = RETURN_ERR;
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
    exit(STATUS_ERR);
    return;
  }

  /* Check if the file descriptor is valid. */
  if (fd == STDOUT_FILENO) {
    /* Cannot read from stdout. */
    f->eax = RETURN_ERR;
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
      f->eax = RETURN_ERR;
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

/* Maps the file open as fd into the process's virtual address space. */
static void
sys_mmap (struct intr_frame *f) 
{
  /* Loads the file descriptor and address from the stack. */
  int fd = load_number_from_vaddr(get_arg_1(f->esp));
  void *addr = load_address_from_vaddr(get_arg_2(f->esp));

  /* Check if the file descriptor is valid. */
  if (fd < BASE_FD) {
    f->eax = RETURN_ERR;
    return;
  }

  /* Check if the address is valid. */
  if (addr == NULL || addr == 0 || addr >= PHYS_BASE || (uintptr_t)addr % PGSIZE != 0) {
    f->eax = RETURN_ERR;
    return;
  }

  /* Get the opened file from the file descriptor. */
  struct o_file *open_file = get_o_file_from_fd(fd);
  if (open_file == NULL) {
    f->eax = RETURN_ERR;
    return;
  }

  /* Get the file length. */
  int length = file_length(open_file->file);

  void *stop = pg_round_up(addr + length);
  if (length == 0 || check_any_mapped(addr, stop)) {
      f->eax = RETURN_ERR;
      return;
  }

  void *kpage = pagedir_get_page(thread_current()->pagedir, addr);
  if (kpage != NULL) {
    f->eax = RETURN_ERR;
    return;
  }

  lock_acquire(&filesys_lock);
  struct file *file = file_reopen(open_file->file);
  lock_release(&filesys_lock);
  if (file == NULL) {
    f->eax = RETURN_ERR;
    return;
  }

  struct thread *cur = thread_current();
  void *vaddr = addr;
  size_t remaining_bytes = length;
  size_t offset = 0;
  while (remaining_bytes > 0) {
      size_t page_read_bytes = remaining_bytes < PGSIZE ? remaining_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct page *p = malloc(sizeof(struct page));
      if (p == NULL) {
          f->eax = RETURN_ERR;
          return;
      }

      p->vaddr = vaddr;
      p->file = file;
      p->offset = offset;
      p->read_bytes = page_read_bytes;
      p->writable = true;
      p->is_mmap = true;

      if (!supp_page_table_insert(&cur->pg_table, p)) {
          free(p);
          f->eax = RETURN_ERR;
          return;
      }

      vaddr += PGSIZE;
      offset += page_read_bytes;
      remaining_bytes -= page_read_bytes;
  }

  /* Create a new memory mapped file. */
  struct mapid_file *new_mapid_file = malloc(sizeof(struct mapid_file));
  if (new_mapid_file == NULL) {
    f->eax = RETURN_ERR;
    return;
  }

  /* Set the mapid and file and insert into mmap_table. */
  new_mapid_file->file = file;
  new_mapid_file->mapid = cur->next_mapid++;
  hash_insert(&cur->mmap_table, &new_mapid_file->mapid_elem);

  /* Return the mapping ID. */
  f->eax = new_mapid_file->mapid;
}

void
munmap(int mapid)
{
  /* Just call sys_munmap with the given mapid. */
  struct intr_frame f;
  f.esp = (uint8_t *) &mapid - 4;
  sys_munmap(&f);
}

/* Unmaps the memory mapped file from the process's virtual address space. */
static void
sys_munmap (struct intr_frame *f) 
{
  /* Load the mapping ID from the stack. */
  int mapid = load_number_from_vaddr(get_arg_1(f->esp));

  /* Get the memory mapped file from the mapping ID. */
  struct mapid_file *mmap_file = get_mmap_file_from_mapid(mapid);
  if (mmap_file == NULL) {
    return;
  }

  struct thread *cur = thread_current();
  struct file *file = mmap_file->file;

  struct hash_iterator i;
  hash_first(&i, &cur->pg_table);
  while (hash_next(&i)) {
      struct page *p = hash_entry(hash_cur(&i), struct page, elem);
      if (p->file == file && p->is_mmap) {
          if (pagedir_is_dirty(cur->pagedir, p->vaddr)) {
              lock_acquire(&filesys_lock);
              file_write_at(file, p->vaddr, p->read_bytes, p->offset);
              lock_release(&filesys_lock);
          }
          pagedir_clear_page(cur->pagedir, p->vaddr);
      }
  }

  /* Remove the memory mapped file from the hash table. */
  hash_delete(&thread_current()->mmap_table, &mmap_file->mapid_elem);

  /* Close the file. */
  lock_acquire(&filesys_lock);
  file_close(mmap_file->file);
  lock_release(&filesys_lock);
}

/* Get the memory mapped file from the mapping ID. */
static struct mapid_file *
get_mmap_file_from_mapid(int mapid) 
{
  /* Set the mapping ID. */
  struct mapid_file search_mapid_file;
  search_mapid_file.mapid = mapid;

  /* Search for the memory mapped file in the hash table. */
  struct thread *cur = thread_current();
  struct hash_elem *found_mapid_elem = hash_find(&cur->mmap_table, &search_mapid_file.mapid_elem);
  if (found_mapid_elem == NULL) {
    return NULL;
  }

  /* Return the memory mapped file. */
  struct mapid_file *mmap_file = hash_entry(found_mapid_elem, struct mapid_file, mapid_elem);
  return mmap_file;
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

/* Exits the current thread with the given status. */
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

/* Hash function for memory mapped files. */
unsigned
mmap_hash(const struct hash_elem *e, void *aux UNUSED) {
  const struct mapid_file *mf = hash_entry(e, struct mapid_file, mapid_elem);
  return hash_int(mf->mapid);
}

/* Comparison function for memory mapped files. */
bool
mmap_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
  const struct mapid_file *mf_a = hash_entry(a, struct mapid_file, mapid_elem);
  const struct mapid_file *mf_b = hash_entry(b, struct mapid_file, mapid_elem);
  return mf_a->mapid < mf_b->mapid;
}

static bool check_any_mapped(void *start, void *stop) {
    ASSERT(start <= stop);
    struct thread *cur = thread_current();

    /* Align start and stop to page boundaries */
    start = pg_round_down(start);
    stop = pg_round_down(stop);

    for (void *addr = start; addr <= stop; addr += PGSIZE) {
        /* Check if the page is already mapped */
        if (supp_page_table_get(&cur->pg_table, addr) != NULL) {
            return true;
        }

        /* Check if the page overlaps with the stack */
        if (addr >= PHYS_BASE - 8388608 && addr < PHYS_BASE) {
            return true;
        }
    }
    return false;
}
