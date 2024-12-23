#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "devices/swap.h"
#include "threads/thread.h"
#include "lib/kernel/bitmap.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp, char **argv, int argc);
static struct link *valid_child_tid(tid_t child_tid);
static void fd_destroy(struct hash_elem *e, void *aux UNUSED);
static void page_destroy(struct hash_elem *e, void *aux UNUSED);
static void mapping_destroy(struct hash_elem *e, void *aux UNUSED);
static void trim_command(const char *str, const char **start, const char **end);
static int num_args(const char *command);

struct o_file *
get_o_file_from_fd(int fd) {
    /* Check if input fd is valid. */
    if (fd < BASE_FD) {
        return NULL;
    }
    struct thread *cur = thread_current();

    /* Get the corresponding opened file from the hash map. */
    struct o_file search_open_file;
    search_open_file.fd = fd;

    /* Find file in fd hash table. */
    struct hash_elem *found_file_elem = hash_find(&cur->file_descriptors, &search_open_file.fd_elem);

    /* File not found, return NULL. */
    if (found_file_elem == NULL) {
        return NULL;
    }

    /* Else, return the file. */
    struct o_file *open_file = hash_entry(found_file_elem, struct o_file, fd_elem);
    return open_file;
}

/* Trim leading and trailing whitespace from a string.
   This does not modify the command string. It returns
   pointers to the start and end of the trimmed string.
   Usage:
    char *start, *end;
    trim(str, &start, &end);
*/
static void
trim_command(const char *str, const char **start, const char **end)
{
  /* Find the start of the string */
  *start = str;
  while (**start == ' ')
    (*start)++;

  /* Find the end of the string */
  *end = *start;
  while (**end != '\0')
    (*end)++;
  (*end)--;

  /* Trim trailing whitespace */
  while (**end == ' ')
    (*end)--;
  (*end)++;
}

/* Count the number of arguments in a command string */
static int
num_args(const char *command)
{
  int argc = 0;

  /* Trim leading and trailing whitespace */
  const char *start, *end;
  trim_command(command, &start, &end);

  /* Iterate through the command string and count the number of space */
  const char *c = start;
  while (c < end) {
    if (*c == ' ') {
      /* Skip multiple spaces */
      while (*c == ' ') {
        c++;
      }
      argc++;
    }
    c++;
  }
  return argc + 1;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *command) 
{
  char *fn_copy;
  tid_t tid;

  /* Ensure arguments can fit on one page */
  if (strlen(command) + 1 >= PGSIZE) {
    return TID_ERROR;
  }

  /* Ensure the number of arguments is less than MAX_ARGS */
  if (num_args(command) > MAX_ARGS) {
    return TID_ERROR;
  }

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, command, PGSIZE);

  /* Extract the command name from the command string */
  char *command_name = malloc(strlen(command) + 1);
  if (command_name == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  strlcpy(command_name, command, strlen(command) + 1);
  char *save_ptr;
  char *token = strtok_r(command_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (token, PRI_DEFAULT, start_process, fn_copy);

  /* Get link with child */
  struct link *child_link = valid_child_tid(tid);
  if (child_link == NULL) {
    return TID_ERROR;
  }

  /* Wait for child to load */
  sema_down(&child_link->load_sema);
  if (child_link->load_status == LOAD_FAILED) {
    return TID_ERROR;
  }

  /* Free the command name and command copy */
  free(command_name);
  palloc_free_page (fn_copy);

  if (thread_current()->exec_file != NULL) {
    /* Share pages if the child has the same executable */
    if (file_compare(thread_current()->exec_file, child_link->child->exec_file)) {
      struct hash_iterator i;
      hash_first(&i, &thread_current()->spt);
      while (hash_next(&i))
        {
          struct page *p = hash_entry(hash_cur(&i), struct page, elem);

          lock_acquire(&p->data->lock);

          if (p->data->writable || p->data->is_mmap) {
            lock_release(&p->data->lock);
            continue;
          }
          lock_release(&p->data->lock);

          /* Allocate a page */
          struct page *new_page = page_alloc(p->vaddr, p->data->writable);
          if (new_page == NULL) {
            return TID_ERROR;
          }
          
          /* Remove the new page from old data's list of pages */
          lock_acquire(&p->data->lock);
          list_remove(&new_page->data_elem);
          lock_release(&p->data->lock);

          /* Free the old data */
          free(new_page->data);
          
          /* Share the same shared_data structure */
          new_page->data = p->data;

          /* Add the new page to the new data's list of pages */
          lock_acquire(&new_page->data->lock);
          list_push_back(&new_page->data->pages, &new_page->data_elem);
          lock_release(&new_page->data->lock);

          /* Insert the new page into the child's SPT */
          spt_insert(&child_link->child->spt, new_page);
        }
    }
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *command_)
{
  char *command = command_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  /* Tokenise the command string */
  char *argv[MAX_ARGS];
  int argc = 0;
  char *token, *save_ptr;
  for (token = strtok_r (command, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr))
    {
      argv[argc] = token;
      argc++;
    }

  /* Load the executable file */
  success = load (argv[0], &if_.eip, &if_.esp, argv, argc);

  /* Set the load status of the current thread */
  struct thread *cur = thread_current();
  lock_acquire(&cur->pLink->lock);
  cur->pLink->load_status = success ? LOAD_SUCCESS : LOAD_FAILED;
  lock_release(&cur->pLink->lock);

  /* Signal parent that load has completed */
  sema_up(&cur->pLink->load_sema);

  /* If load failed, quit. */
  if (!success) {
    exit(STATUS_ERR);
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{
  /* Get child link */
  struct link *child_link = valid_child_tid(child_tid);

  /* Exit if the child_tid is not a valid child of the current thread */
  if (child_link == NULL)
    return STATUS_ERR;

  /* Wait for the child to exit */
  sema_down(&child_link->sema);

  /* Get the exit status of the child */
  lock_acquire(&child_link->lock);
  int exit_status = child_link->exit_status;
  lock_release(&child_link->lock);

  /* Remove the link between the parent and child */
  list_remove(&child_link->elem);

  /* Free the link */
  free(child_link);

  return exit_status;
}

/* Returns the child thread if it is valid, otherwise NULL. */
static struct link *
valid_child_tid(tid_t child_tid)
{
  struct thread *parent = thread_current();
  
  /* Iterate through the parent's list of child links. */
  struct list_elem *e;
  for (e = list_begin(&parent->cLinks); e != list_end(&parent->cLinks); e = list_next(e))
    {
      struct link *link = list_entry(e, struct link, elem);

      lock_acquire(&link->lock);

      /* If the child's tid matches the given tid, return it */
      if (link->child_tid == child_tid)
        {
          lock_release(&link->lock);
          return link;
        }

      lock_release(&link->lock);
    }

  return NULL;
}

/* Destructor function for the file descriptor hash table. */
static void
fd_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct o_file *file = hash_entry(e, struct o_file, fd_elem);
  lock_acquire(&filesys_lock);
  file_close(file->file);
  lock_release(&filesys_lock);
  free(file);
}

/* Destructor function for the page table hash table. */
static void
page_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct page *p = hash_entry(e, struct page, elem);
  free(p);
}

/* Destructor function for the mapping hash table. */
static void
mapping_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct mapid_file *m = hash_entry(e, struct mapid_file, mapid_elem);
  free(m);
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Unmap all memory mapped files */
  struct hash_iterator i;
  hash_first(&i, &cur->mmap_table);
  while (hash_next(&i))
    {
      struct mapid_file *m = hash_entry(hash_cur(&i), struct mapid_file, mapid_elem);
      munmap(m->mapid);
    }

  /* Free swap slots used by the process. */
  struct hash_iterator j;
  hash_first(&j, &cur->spt);
  while (hash_next(&j))
  {
    struct page *p = hash_entry(hash_cur(&j), struct page, elem);
    bool cur_holds_data_lock = lock_held_by_current_thread(&p->data->lock);
    if (!cur_holds_data_lock)
      lock_acquire(&p->data->lock);

    if (p->data->swap_slot != BITMAP_ERROR)
      {
        swap_drop(p->data->swap_slot);
        p->data->swap_slot = BITMAP_ERROR;
      }
    if (!cur_holds_data_lock)
      lock_release(&p->data->lock);
  }

  /* Free hash table and containing data */
  hash_destroy(&cur->file_descriptors, fd_destroy);
  hash_destroy(&cur->spt, page_destroy);
  hash_destroy(&cur->mmap_table, mapping_destroy);

  /* Allow write back to executable once exited */
	if (cur->exec_file != NULL)
	{
	  lock_acquire (&filesys_lock);
		file_close (cur->exec_file);
	  lock_release (&filesys_lock);
	}

  /* Print the exit status */
  printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* Clean up the child links by either freeing them if the child has
     already exited, or setting the link->parent to NULL otherwise. */
  struct list_elem *e = list_begin(&cur->cLinks);
  while (e != list_end(&cur->cLinks))
    {
      struct link *link = list_entry(e, struct link, elem);

      lock_acquire(&link->lock);
      
      /* If the current thread's child has exited then free the link,
         otherwise set the link's parent to NULL. */
      if (link->child == NULL)
        {
          lock_release(&link->lock);
          e = list_next(e);
          free(link);
        }
      else
        {
          link->parent = NULL;
          e = list_next(e);
          lock_release(&link->lock);
        }
    }
  
  /* Clean up the link between the current thread and the parent thread */
  struct link *link = cur->pLink;
  if (link != NULL)
    {
      lock_acquire(&link->lock);

      /* If the current thread's parent has exited then free the link,
          otherwise set the link's child to NULL and unblock the parent. */
      if (link->parent == NULL)
        {
          lock_release(&link->lock);
          free(link);
        }
      else
        {
          link->child = NULL;
          link->exit_status = cur->exit_status;
          sema_up(&link->sema);
          lock_release(&link->lock);
        }
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char **argv, int argc);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp, char **argv, int argc) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire(&filesys_lock);
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write(file);
  t->exec_file = file;

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, argv, argc))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  lock_release(&filesys_lock);
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      struct page *page = page_create(upage, writable);
      if (page == NULL) {
        return false;
      }
      lock_acquire(&page->data->lock);
      page->data->file = file;
      page->data->offset = ofs;
      page->data->read_bytes = page_read_bytes;
      lock_release(&page->data->lock);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char **argv, int argc) 
{
  struct page *kpage;
  bool success = false;
  void *uaddr = ((uint8_t *) PHYS_BASE) - PGSIZE;

  /* Allocate a new page to the stack. */
  kpage = page_create(uaddr, true);

  /* Allocate a frame for the page since first page in stack is not lazy loaded. */
  struct frame *frame = load_page(kpage);
  success = frame != NULL;
  if (kpage != NULL && kpage->data->frame != NULL) 
    {
      if (success)
        {
          /* Start at the bottom of the stack */
          *esp = PHYS_BASE;

          /* Push the arguments onto the stack */
          for (int i = argc - 1; i >= 0; i--)
            {
              size_t len = strlen (argv[i]) + 1;

              /* Increase stack size by length of argument */
              *esp -= len;

              /* Copy the argument onto the stack */
              strlcpy (*esp, argv[i], len);

              /* Make the argument pointer point to the address in the stack */
              argv[i] = *esp;
            }

          /* Word align */
          *esp = (void *)((uintptr_t) *esp & WORD_ALIGN_MASK);

          /* Push null pointer sentinel */
          *esp -= sizeof (char *);
          *((char **) *esp) = NULL;

          /* Push arguments' addresses */
          for (int i = argc - 1; i >= 0; i--)
            {
              *esp -= sizeof (char *);
              *((char **) *esp) = argv[i];
            }
          
          /* Push argv */
          char **argv_ptr = *esp;
          *esp -= sizeof (char **);
          *((char ***) *esp) = argv_ptr;

          /* Push argc */
          *esp -= sizeof (int);
          *((int *) *esp) = argc;

          /* Push fake return address */
          *esp -= sizeof (void *);
          *((void **) *esp) = NULL;
        }
      else
        frame_free(kpage->data->frame);
    }
  return success;
}

/* Allocate a new page to the stack,
   where faddr is the fault address
*/
bool
frame_alloc_stack(void *esp, void* faddr) {

  if (esp == NULL) {
    /* May be called before stack has been set up, if so handle case. */
    return false;
  }

  struct page *kpage;

  /* New page if the fault address is within bounds of the stack and pages can still be created. */
  if ((faddr >= esp || faddr == esp - 4 || faddr == esp - 32) && 
        pg_round_down(faddr) >= PHYS_BASE - MAX_STACK_SIZE && faddr < PHYS_BASE) {

    bool success = false;

    void* new_stack_addr = pg_round_down(esp);

    /* Handle edge case when esp is at the page border. */
    if (pg_ofs(esp) == 0) {
      new_stack_addr = pg_round_down(esp - PGSIZE);
    }
    
    kpage = page_create(new_stack_addr, true);
    return kpage != NULL;
  }

  return false;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
