#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"

struct frame {
    void *addr;        // Address of the frame.
    uint8_t *page;       // Pointer to the page occupying this frame.
    struct thread *owner;    // Thread owning the page.
    bool pinned;             // Flag to indicate if the frame is pinned.
    struct hash_elem elem;   // List element for maintaining frame table as a linked list.
};

struct hash frame_table;    // Frame table.
struct lock frame_lock;     // Lock for synchronizing frame table access.

void frame_table_init(void);
void *frame_alloc(enum palloc_flags pal, uint8_t *page);
void frame_free(void *frame_addr);

#endif /* vm/frame.h */