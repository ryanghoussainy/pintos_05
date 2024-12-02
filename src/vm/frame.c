#include "vm/frame.h"
#include "vm/page.h"
#include "devices/swap.h"

static unsigned
frame_hash(const struct hash_elem *elem, void *aux UNUSED) {
    const struct frame *f = hash_entry(elem, struct frame, elem);
    return hash_bytes(&f->addr, sizeof f->addr);
}

static bool
frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct frame *f_a = hash_entry(a, struct frame, elem);
    const struct frame *f_b = hash_entry(b, struct frame, elem);
    return f_a->addr < f_b->addr;
}

void
frame_table_init(void) {
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_lock);
}

static struct frame *clock_hand = NULL;

static struct frame *
frame_choose_victim(void) {
    struct hash_iterator i;
    struct frame *victim = NULL;

    lock_acquire(&frame_lock);

    if (clock_hand == NULL) {
        hash_first(&i, &frame_table);
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
    }
    
    while (victim == NULL) {
        if (!clock_hand->pinned) {
            if (pagedir_is_accessed(clock_hand->owner->pagedir, clock_hand->page)) {
                pagedir_set_accessed(clock_hand->owner->pagedir, clock_hand->page, false);
            } else {
                victim = clock_hand;
            }
        }

        hash_next(&i);
        if (hash_cur(&i) == NULL) {
            hash_first(&i, &frame_table);
        }
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
    }
    
    lock_release(&frame_lock);
    ASSERT(victim != NULL); // Ensure there is a valid frame to evict
    return victim;
}

static void
frame_evict(void) {
    struct frame *victim = frame_choose_victim();
    ASSERT(victim != NULL);

    struct thread *owner = victim->owner;
    struct page *page = pagedir_get_page(owner->pagedir, victim->page);

    if (page != NULL) {
        // Swap out the page
        size_t swap_slot = swap_out(victim->addr);
        if (swap_slot == -1) {
            PANIC("Swap failed during eviction");
        }

        // Update supplemental page table
        page->vaddr = NULL; // Invalidate virtual address mapping
        page->swap_slot = swap_slot; // Save swap slot index
    }

    // Free physical frame
    hash_delete(&frame_table, &victim->elem);
    palloc_free_page(victim->addr);
    free(victim);
}


void *
frame_alloc(enum palloc_flags pal, uint8_t *page) {
    struct thread *cur = thread_current();

    void *frame = palloc_get_page(pal);
    if (frame == NULL) {
        /* Evict a frame */
        frame_evict();
        frame = palloc_get_page(pal);
        if (frame == NULL) {
            PANIC("Out of memory: frame allocation failed after eviction");
        }
    }

    // Allocate frame table entry.
    struct frame *f = malloc(sizeof(struct frame));
    if (f == NULL) {
        palloc_free_page(frame);
        PANIC("Out of memory: frame table entry allocation failed");
    }

    f->addr = frame;
    f->page = page;
    f->owner = cur;
    f->pinned = false;

    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &f->elem);
    lock_release(&frame_lock);

    return frame;
}

void
frame_free(void *frame_addr) {
    lock_acquire(&frame_lock);

    struct frame f;
    f.addr = frame_addr;
    struct hash_elem *e = hash_find(&frame_table, &f.elem);
    if (e == NULL) {
        lock_release(&frame_lock);
        PANIC("Frame not found in frame table");
    }

    struct frame *f_entry = hash_entry(e, struct frame, elem);
    hash_delete(&frame_table, &f_entry->elem);
    pagedir_clear_page(f_entry->owner->pagedir, f_entry->page);
    palloc_free_page(f_entry->addr);
    free(f_entry);

    lock_release(&frame_lock);
}

