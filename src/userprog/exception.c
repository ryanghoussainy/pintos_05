#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "lib/string.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "devices/swap.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);

      thread_current()->exit_status = -1;
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  
         Shouldn't happen.  Panic the kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      PANIC ("Kernel bug - this shouldn't be possible!");
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;  /* True: not-present page, false: writing r/o page. */
  bool write;        /* True: access was write, false: access was read. */
  bool user;         /* True: access by user, false: access by kernel. */
  void *fault_addr;  /* Fault address. */

  /* Obtain faulting address, the virtual address that was
     accessed to cause the fault.  It may point to code or to
     data.  It is not necessarily the address of the instruction
     that caused the fault (that's f->eip).
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
     (#PF)". */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* Turn interrupts back on (they were only off so that we could
     be assured of reading CR2 before it changed). */
  intr_enable ();

   /* If the fault address appears to be in stack range then grow,
      otherwise continue */
  if (frame_alloc_stack(f->esp, fault_addr)) {
   return;
  }

  void *fault_page = pg_round_down(fault_addr);

  /* Check if the faulting page is in the supplemental page table */
  struct thread *cur = thread_current();
  struct page p;
  p.vaddr = fault_page;
  struct hash_elem *e = hash_find (&cur->pg_table, &p.elem);
  if (e == NULL) {
    goto page_fault;
  }
  struct page *found_page = hash_entry (e, struct page, elem);

  /* Check if the page is read-only. */
  if (found_page->file != NULL && !found_page->writable) {
      /* Acquire lock for shared page table to ensure synchronisation. */
      lock_acquire(&shared_page_lock);

      /* Look up the shared page in the global table */
      struct shared_page_entry lookup;
      lookup.file = found_page->file;
      lookup.offset = found_page->offset;
      struct hash_elem *shared_e = hash_find(&shared_page_table, &lookup.elem);
      if (shared_e != NULL) {
          /* Reuse the shared frame. */
          struct shared_page_entry *shared_entry = hash_entry(shared_e, struct shared_page_entry, elem);
          shared_entry->ref_count++;
          lock_release(&shared_page_lock);

          /* Map the shared frame to the faulting page. */
          if (!install_page(fault_page, shared_entry->frame, found_page->writable)) {
              lock_acquire(&shared_page_lock);
              shared_entry->ref_count--;
              lock_release(&shared_page_lock);
              goto page_fault;
          }
          return;
      }
      lock_release(&shared_page_lock);
  }

   /* Page not shared, allocate a new frame and load the page. */
   void *frame = frame_alloc(PAL_USER, found_page->vaddr);
   if (frame == NULL) {
         PANIC("Out of memory: Frame allocation failed.");
   }

   /* Load data into the frame */
   if (found_page->file != NULL) {
      lock_acquire(&filesys_lock);
      if (file_read_at(found_page->file, frame, found_page->read_bytes, found_page->offset) != (int) found_page->read_bytes) {
            frame_free(frame);
            lock_release(&filesys_lock);
            goto page_fault;
      }
      lock_release(&filesys_lock);
      memset(frame + found_page->read_bytes, 0, PGSIZE - found_page->read_bytes);

      /* Add the page to the shared table */
      lock_acquire(&shared_page_lock);
      struct shared_page_entry *new_entry = malloc(sizeof(struct shared_page_entry));
      new_entry->file = found_page->file;
      new_entry->offset = found_page->offset;
      new_entry->frame = frame;
      new_entry->ref_count = 1;
      hash_insert(&shared_page_table, &new_entry->elem);
      lock_release(&shared_page_lock);

      /* Install the page */
      if (!install_page(fault_page, frame, found_page->writable)) {
            lock_acquire(&shared_page_lock);
            new_entry->ref_count--;
            if (new_entry->ref_count == 0) {
               hash_delete(&shared_page_table, &new_entry->elem);
               free(new_entry);
            }
            lock_release(&shared_page_lock);
            frame_free(frame);
            goto page_fault;
      }
      return;
   } else if (found_page->swap_slot != (size_t) -1) {
         swap_in(frame, found_page->swap_slot);
         found_page->swap_slot = (size_t) -1;
   } else {
         memset(frame, 0, PGSIZE);
   }

  /* Install the page */
  if (!install_page(fault_page, frame, found_page->writable)) {
      frame_free(frame);
      goto page_fault;
  }

  return;

page_fault:
  /* Count page faults. */
  page_fault_cnt++;

  /* Determine cause. */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* To implement virtual memory, delete the rest of the function
     body, and replace it with code that brings in the page to
     which fault_addr refers. */
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);

  /* If fault occurred in user mode, terminate the process. */
   if (user) {
      thread_current()->exit_status = -1;
      kill(f);
   } else {
      PANIC("Page fault in kernel mode");
   }
}
