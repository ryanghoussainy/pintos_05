#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"

struct frame {
    void *addr;        // Address of the frame.
    uint8_t *page;       // Pointer to the page occupying this frame.
    struct thread *owner;    // Thread owning the page.
    bool pinned;             // Flag to indicate if the frame is pinned.
    bool reference_bit;      // Reference bit for clock algorithm.
    struct hash_elem elem;   // List element for maintaining frame table as a linked list.
};

struct hash frame_table;    // Frame table.
struct lock frame_lock;     // Lock for synchronizing frame table access.

struct shared_page_entry {
    struct file *file;      // File associated with the page.
    uint32_t offset;        // Offset of the page in the file.
    void *frame;            // Frame currently holding the page.
    int ref_count;          // Number of processes sharing this page.
    struct hash_elem elem;  // Hash element for maintaining shared page table as a linked list.
};

/* Shared page table. */
struct hash shared_page_table;

/* Lock for synchronizing shared page table access. */
struct lock shared_page_lock;  

void frame_table_init(void);
void shared_page_table_init(void);
void *frame_alloc(enum palloc_flags pal, uint8_t *page);
void frame_free(void *frame_addr);

#endif /* vm/frame.h */