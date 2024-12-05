#include "vm/frame.h"
#include "vm/page.h"
#include "devices/swap.h"
#include "userprog/syscall.h"
#include "filesys/file.h"

/* Static pointer used for the Clock algorithm. */
static struct frame *clock_hand;

static void frame_evict(struct frame *victim);
static struct frame *frame_choose_victim(void);
static bool lock_frame(struct frame *frame);
static unsigned frame_hash(const struct hash_elem *elem, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

struct hash_iterator hit;


/* Initialise frame table. */
void
frame_table_init(void) {
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_lock);
    clock_hand = NULL;
}

/* Allocates a frame and adds it to the frame table. */
struct frame *
frame_alloc(struct page *page) {
    struct frame *f;

    /* Allocate a frame. */
    void *faddr = palloc_get_page(PAL_USER | PAL_ZERO);

    /* Evict a frame from page table and reuse it. */
    if (!faddr) {
        lock_acquire(&frame_lock);
        /* Evict a frame if no memory is available. */
        f = frame_choose_victim();
        frame_evict(f);
        // faddr = palloc_get_page(PAL_USER | PAL_ZERO);

        /* Panic if frame allocation fails after eviction. */
        if (f == NULL) {
            PANIC("Out of memory: frame allocation failed after eviction");
        }

        f->data = page->data;
        lock_release(&frame_lock);
        return f;
    }
    // } else {
    // /* Allocate frame table entry. */
    //     struct frame *f = malloc(sizeof(struct frame));
    //     if (f == NULL) {
    //         palloc_free_page(faddr);
    //         PANIC("Out of memory: frame table entry allocation failed");
    //     }
    //     f->addr = faddr;
    //     f->page = page;
    //     f->owner = cur;
    //     f->pinned = false;
    //     lock_acquire(&frame_lock);
    //     hash_insert(&frame_table, &f->elem);
    //     lock_release(&frame_lock);
    // }

    struct frame *frame = malloc(sizeof(struct frame));
    if (frame == NULL) {
        palloc_free_page(faddr);
        PANIC("Out of memory: frame table entry allocation failed");
    }
    frame->addr = faddr;
    
    // frame->pinned = false;
    frame->data = page->data;
    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &frame->elem);
    lock_release(&frame_lock);

    /* Initialise frame table entry. */
    // f->addr = faddr;
    // f->page = page;
    // f->owner = cur;
    // f->pinned = false;


    /* Insert frame table entry into hash table. */
    // lock_acquire(&frame_lock);
    // hash_insert(&frame_table, &f->elem);
    // lock_release(&frame_lock);
    return frame;
}

/* Frees a frame from the frame table. */
void
frame_free(struct frame *frame) {

    lock_acquire(&frame_lock);
    hash_delete(&frame_table, &frame->elem);
    lock_release(&frame_lock);
    // pagedir_clear_page(f_entry->owner->pagedir, f_entry->page);

    // Clear each page in the frame->pages list
    // struct list_elem *pe;
    // for (pe = list_begin(&f_entry->data->pages); pe != list_end(&f_entry->data->pages); pe = list_next(pe)) {
    //     struct page *p = list_entry(pe, struct page, data_elem);
    //     pagedir_clear_page(p->owner->pagedir, p->vaddr);
    // }
    palloc_free_page(frame->addr);
    free(frame);
}

/* Evicts a frame from the frame table. */
static void
frame_evict(struct frame *victim) {
    /* Choose a victim frame to evict. */
    // struct frame *victim = frame_choose_victim();
    ASSERT(victim != NULL);
    // struct thread *owner = victim->owner;
    // ASSERT(owner != NULL);

    // struct shared_data *data = victim->page->data;

    // if (owner == NULL || owner->status == THREAD_DYING) {
    //     hash_delete(&frame_table, &victim->elem);
    //     palloc_free_page(victim->addr);
    //     free(victim);
    //     lock_release(&frame_lock);
    //     // Try again?
    // }

    // struct shared_data *data = victim->page->data;
    // lock_acquire(&data->lock);

    struct list pages = victim->data->pages;

    struct list_elem *e;
    for (e = list_begin(&pages); e != list_end(&pages); e = list_next(e)) {
        struct page *page = list_entry(e, struct page, data_elem);
        
        bool dirty = pagedir_is_dirty(page->owner->pagedir, page->vaddr);

        if (dirty) {
            /* Swap out the page if it is dirty. */
            size_t swap_slot = swap_out(victim->addr);
            if (swap_slot == (size_t) -1) {
                // lock_release(&data->lock);
                PANIC("Swap failed during eviction");
            }

            page->data->swap_slot = swap_slot; // Save swap slot index
        }

        /* Update supplemental page table. */
        page->data->frame->data = NULL;
        page->data->frame = NULL;
    }

    /* Get the page associated with the frame. */
    // struct page *page = supp_page_table_get(&owner->pg_table, victim->page->vaddr);
    // if (page == NULL) {
    //     hash_delete(&frame_table, &victim->elem);
    //     palloc_free_page(victim->addr);
    //     free(victim);
    //     lock_release(&frame_lock);
    //     // Try again?
    // }

    /* Check if the page is dirty. */  
    // bool dirty = pagedir_is_dirty(owner->pagedir, victim->page->vaddr);

    // if (dirty) {
    //     /* Swap out the page if it is dirty. */
    //     size_t swap_slot = swap_out(victim->addr);
    //     if (swap_slot == (size_t) -1) {
    //         // lock_release(&data->lock);
    //         PANIC("Swap failed during eviction");
    //     }

    //     /* Update supplemental page table. */
    //     page->data->frame = NULL;
    //     page->data->swap_slot = swap_slot; // Save swap slot index
    // }

    /* Invalidate the page from the owner's page directory. */
    // pagedir_clear_page(owner->pagedir, victim->page);

    /* Remove frame from the frame table and free physical frame. */
    // hash_delete(&frame_table, &victim->elem);
    // lock_release(&data->lock);

    // palloc_free_page(victim->addr);
    // free(victim);

  if ((data->file && !data->is_mmap) || !data->file)
    {
        /* Store the page into a swap slot
        * if loaded from an executable or zero page. */
        data->swap_slot = swap_out (data->frame->addr);
        /* Return false if the swap slot is full. */
        if (data->swap_slot == (size_t) -1)
        PANIC ("Failed to swap out page during eviction");
        data->swapped = true;
        data->frame = NULL;
        // lock_release (&data->lock);
        return;
    }
  if (data->file && data->is_mmap)
    {
        /* Store the page into the file if memory mapped.
        * No need to write back if the page is not dirty. */
        if (pagedir_are_any_dirty (&data->pages))
        {
        //   if (lock_held_by_current_thread (&filesys_lock))
            // release_file_lock ();
        int written_bytes = file_write_at (data->file, data->frame->addr, data->read_bytes, data->offset);
        //   if (acquired)
            // release_file_lock ();
        if (data->read_bytes != (size_t) written_bytes)
        {
            // lock_release (&data->lock);
            PANIC ("Failed to write back memory mapped page during eviction");
        }
        }
        data->frame = NULL;
        // lock_release (&data->lock);
        return;
    }
}

/* Chooses a frame to evict using the Clock algorithm. */
static struct frame *
frame_choose_victim(void) {
    struct hash_iterator i;
    struct frame *victim = NULL;

    /* If the clock hand is NULL, start from the beginning of the frame table. */
    if (clock_hand == NULL) {
        hash_first(&i, &frame_table);
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
    }
    
    /* Iterate through the frame table until a victim is found. */
    while (victim == NULL) {
        // if (!clock_hand->pinned) {
        // lock_acquire(&frame_lock);
            // if (pagedir_is_accessed(clock_hand->owner->pagedir, clock_hand->page->vaddr)) {
            //     pagedir_set_accessed(clock_hand->owner->pagedir, clock_hand->page->vaddr, false);
            //     // clock_hand->pinned = false;
            // } else {
            //     victim = clock_hand;
            // }

            struct list pages = clock_hand->data->pages;
            bool none_accessed = true;

            struct list_elem *e;
            for (e = list_begin(&pages); e != list_end(&pages); e = list_next(e)) {
                struct page *page = list_entry(e, struct page, data_elem);
                if (pagedir_is_accessed(page->owner->pagedir, page->vaddr)) {
                    pagedir_set_accessed(page->owner->pagedir, page->vaddr, false);
                    none_accessed = false;
                    break;
                }
            }

            // Choose this frame
            if (none_accessed) {
                victim = clock_hand;
            }
        // lock_release(&frame_lock);
        // }

        /* Move the clock hand to the next frame. */
        hash_next(&i);
        if (hash_cur(&i) == NULL) {

            hash_first(&i, &frame_table);
        }
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
    }

    /* Ensure that a victim was found. */
    ASSERT(victim != NULL); 
    return victim;
    

    // PANIC ("Failed to lock frame during eviction");
    // return victim;
}

// static bool 
// lock_frame (struct frame *frame)
// {
//     if (frame->pinned && lock_held_by_current_thread(&frame_lock))
//     {
//         return false;
//     }
//     frame->pinned = true;
//     lock_acquire(&frame_lock);
//     return true;
// }

// /* Pins a frame to prevent it being evicted */
// bool
// pin_frame(void *vaddr) {
//     struct thread *cur = thread_current();
//     struct page *page = supp_page_table_get(&cur->pg_table, vaddr);
//     if (page) {
//         if (page->data == NULL || page->data->frame == NULL) {
//             // Load the page if it's not in memory
//             if (load_page(page) == NULL) {
//                 return false;
//             }
//             if (!install_page(page->vaddr, page->data->frame->addr, page->data->writable)) {
//                 return false;
//             }
//         }
//         lock_acquire(&frame_lock);
//         page->data->frame->pinned = true;
//         lock_release(&frame_lock);
//         return true;
//     } else {
//         return false;
//     }
// }

// /* Unpin a frame to allow eviction again */
// void
// unpin_frame(void *vaddr) {
//     struct thread *cur = thread_current();
//     struct page *page = supp_page_table_get(&cur->pg_table, vaddr);
//     if (page != NULL && page->data != NULL && page->data->frame != NULL) {
//         lock_acquire(&frame_lock);
//         page->data->frame->pinned = false;
//         lock_release(&frame_lock);
//     }
// }

/* Frame table hash function. */
static unsigned
frame_hash(const struct hash_elem *elem, void *aux UNUSED) {
    const struct frame *f = hash_entry(elem, struct frame, elem);
    return hash_bytes(&f->addr, sizeof f->addr);
}

/* Frame table comparison function. */
static bool
frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct frame *f_a = hash_entry(a, struct frame, elem);
    const struct frame *f_b = hash_entry(b, struct frame, elem);
    return f_a->addr < f_b->addr;
}
