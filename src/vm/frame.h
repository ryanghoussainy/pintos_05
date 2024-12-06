#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"

/* Number of chances each frame gets in clock algorithm. */
#define TWO_CHANCES 2

struct frame {
    void *addr;                /* Address of the frame. */
    struct shared_data *data;  /* Page occupying this frame. */
    // bool pinned;               /* Flag to indicate if the frame is pinned. */
    // int age;                   /* Age of the frame for clock algorithm. */
    struct hash_elem elem;     /* List element for maintaining frame table as a linked list. */
};

struct hash frame_table;    /* Frame table. */
struct lock frame_lock;     /* Lock for synchronizing frame table access. */

void frame_table_init(void);
struct frame *frame_alloc(struct shared_data *data);
void frame_free(struct frame *frame);

bool pin_frame(void *vaddr);
void unpin_frame(void *vaddr);

#endif /* vm/frame.h */
