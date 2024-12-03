#include "vm/frame.h"
#include "vm/page.h"
#include "devices/swap.h"

/* Static pointer used for the Clock algorithm. */
static struct frame *clock_hand;

static void frame_evict(void);
static struct frame *frame_choose_victim(void);
static unsigned frame_hash(const struct hash_elem *elem, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

/* Initialise frame table. */
void
frame_table_init(void) {
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_lock);
    clock_hand = NULL;
}

/* Allocates a frame and adds it to the frame table. */
void *
frame_alloc(enum palloc_flags pal, uint8_t *page) {
    /* Retrieve the current thread. */
    struct thread *cur = thread_current();

    /* Allocate a frame. */
    void *frame = palloc_get_page(pal);
    if (frame == NULL) {
        /* Evict a frame if no memory is available. */
        frame_evict();
        frame = palloc_get_page(pal);

        /* Panic if frame allocation fails after eviction. */
        if (frame == NULL) {
            PANIC("Out of memory: frame allocation failed after eviction");
        }
    }

    /* Allocate frame table entry. */
    struct frame *f = malloc(sizeof(struct frame));
    if (f == NULL) {
        palloc_free_page(frame);
        PANIC("Out of memory: frame table entry allocation failed");
    }

    /* Initialise frame table entry. */
    f->addr = frame;
    f->page = page;
    f->owner = cur;
    f->pinned = false;

    /* Insert frame table entry into hash table. */
    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &f->elem);
    lock_release(&frame_lock);
    return frame;
}

/* Frees a frame from the frame table. */
void
frame_free(void *frame_addr) {
    /* Acquire frame lock to ensure proper synchronisation. */
    lock_acquire(&frame_lock);

    /* Find the frame in the frame table. */
    struct frame f;
    f.addr = frame_addr;
    struct hash_elem *e = hash_find(&frame_table, &f.elem);
    if (e == NULL) {
        lock_release(&frame_lock);
        PANIC("Frame not found in frame table");
    }

    /* Free the frame and remove it from the frame table. */
    struct frame *f_entry = hash_entry(e, struct frame, elem);
    hash_delete(&frame_table, &f_entry->elem);
    pagedir_clear_page(f_entry->owner->pagedir, f_entry->page);
    palloc_free_page(f_entry->addr);
    free(f_entry);

    /* Release the frame lock. */
    lock_release(&frame_lock);
}

/* Evicts a frame from the frame table. */
static void
frame_evict(void) {
    /* Choose a victim frame to evict. */
    struct frame *victim = frame_choose_victim();
    ASSERT(victim != NULL);
    struct thread *owner = victim->owner;
    ASSERT(owner != NULL);

    /* Acquire frame lock to ensure proper synchronisation. */
    lock_acquire(&frame_lock);

    /* Get the page associated with the frame. */
    struct page *page = pagedir_get_page(owner->pagedir, victim->page);

    if (page != NULL) {
        /* Check if the page is dirty. */  
        bool dirty = pagedir_is_dirty(owner->pagedir, victim->page);

        if (dirty) {
            /* Swap out the page if it is dirty. */
            size_t swap_slot = swap_out(victim->addr);
            if (swap_slot == (size_t) -1) {
                PANIC("Swap failed during eviction");
            }

            /* Update supplemental page table. */
            page->vaddr = NULL; // Invalidate virtual address mapping
            page->data->swap_slot = swap_slot; // Save swap slot index
        }

        /* Invalidate the page from the owner's page directory. */
        pagedir_clear_page(owner->pagedir, victim->page);
    }

    /* Remove frame from the frame table and free physical frame. */
    hash_delete(&frame_table, &victim->elem);
    palloc_free_page(victim->addr);
    free(victim);

    /* Release the frame lock. */
    lock_release(&frame_lock);
}

/* Chooses a frame to evict using the Clock algorithm. */
static struct frame *
frame_choose_victim(void) {
    struct hash_iterator i;
    struct frame *victim = NULL;

    /* Acquire frame lock to ensure proper synchronisation. */
    lock_acquire(&frame_lock);

    /* If the clock hand is NULL, start from the beginning of the frame table. */
    if (clock_hand == NULL) {
        hash_first(&i, &frame_table);
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
    }
    
    /* Iterate through the frame table until a victim is found. */
    while (victim == NULL) {
        if (!clock_hand->pinned) {
            if (pagedir_is_accessed(clock_hand->owner->pagedir, clock_hand->page)) {
                pagedir_set_accessed(clock_hand->owner->pagedir, clock_hand->page, false);
            } else {
                victim = clock_hand;
            }
        }

        /* Move the clock hand to the next frame. */
        hash_next(&i);
        if (hash_cur(&i) == NULL) {

            hash_first(&i, &frame_table);
        }
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
    }
    
    /* Release the frame lock. */
    lock_release(&frame_lock);

    /* Ensure that a victim was found. */
    ASSERT(victim != NULL); 
    return victim;
}

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
