#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

struct frame {
    void *frame_addr;        // Address of the frame.
    struct page *page;       // Pointer to the page occupying this frame.
    struct thread *owner;    // Thread owning the page.
    bool pinned;             // Flag to indicate if the frame is pinned.
    struct list_elem elem;   // List element for maintaining frame table as a linked list.
};

extern struct list frame_table;    // Frame table.
extern struct lock frame_lock;     // Lock for synchronizing frame table access.

void frame_table_init(void);
void *frame_alloc(struct page *page);
void frame_free(void *frame_addr);

#endif /* vm/frame.h */