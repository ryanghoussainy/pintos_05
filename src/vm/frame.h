#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"

struct frame {
    void *addr;              /* Address of the frame. */
    struct page *page;       /* Page occupying this frame. */
    struct thread *owner;    /* Thread owning the page. */
    bool pinned;             /* Flag to indicate if the frame is pinned. */
    bool reference_bit;      /* Reference bit for clock algorithm. */
    struct hash_elem elem;   /* List element for maintaining frame table as a linked list. */
};

struct hash frame_table;    /* Frame table. */
struct lock frame_lock;     /* Lock for synchronizing frame table access. */

void frame_table_init(void);
struct frame *frame_alloc(struct page *page);
void frame_free(struct frame *frame);

#endif /* vm/frame.h */
