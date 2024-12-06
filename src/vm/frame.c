#include "vm/frame.h"
#include "vm/page.h"
#include "devices/swap.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "lib/kernel/bitmap.h"
#include "random.h"

/* Static pointer used for the Clock algorithm. */
static struct frame *clock_hand;

static void frame_evict(struct frame *victim);
static struct frame *frame_choose_victim(void);
static unsigned frame_hash(const struct hash_elem *elem, void *aux UNUSED);
static bool frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);

struct hash_iterator i;

/* Initialise frame table. */
void
frame_table_init(void) 
{
    hash_init(&frame_table, frame_hash, frame_less, NULL);
    lock_init(&frame_lock);
    clock_hand = NULL;
}

/* Allocates a frame and adds it to the frame table. */
struct frame *
frame_alloc(struct shared_data *data) 
{
    struct frame *f;

    /* Allocate a frame. */
    void *faddr = palloc_get_page(PAL_USER | PAL_ZERO);

    /* Evict a frame from page table and reuse it. */
    if (!faddr) {
        lock_acquire(&frame_lock);

        /* Evict a frame if no memory is available. */
        f = frame_choose_victim();
        frame_evict(f);

        /* Panic if frame allocation fails after eviction. */
        if (f == NULL) {
            PANIC("Out of memory: frame allocation failed after eviction");
        }
        f->data = data;
        lock_release(&frame_lock);
        return f;
    }

    /* Allocate a new frame. */
    struct frame *frame = malloc(sizeof(struct frame));
    if (frame == NULL) {
        palloc_free_page(faddr);
        PANIC("Out of memory: frame table entry allocation failed");
    }
    frame->addr = faddr;
    frame->data = data;
    lock_acquire(&frame_lock);
    hash_insert(&frame_table, &frame->elem);
    lock_release(&frame_lock);
    return frame;
}

/* Frees a frame from the frame table. */
void
frame_free(struct frame *frame)
{
    lock_acquire(&frame_lock);

    /* Remove the frame from the frame table. */
    hash_delete(&frame_table, &frame->elem);
    lock_release(&frame_lock);
    palloc_free_page(frame->addr);
    free(frame);
}

/* Evicts the frame passed in from the frame table. */
static void
frame_evict(struct frame *victim) 
{
    /* The frame to be victed is chosen beforehand. */
    ASSERT(victim != NULL);

    /* Retrieve the metadata of the victim frame. */
    struct shared_data *data = victim->data;

    bool cur_holds_data_lock = lock_held_by_current_thread(&data->lock);

    if (!cur_holds_data_lock) {
        lock_acquire(&data->lock);
    }

    /* Clear all pages sharing the same data. */
    struct list_elem *elem;
    for (elem = list_begin (&data->pages); elem != list_end (&data->pages); elem = list_next (elem))
    {
        struct page *page = list_entry (elem, struct page, data_elem);
        pagedir_clear_page (page->owner->pagedir, page->vaddr);
    }

    /* Case 1: Non memory-mapped data segment pages or non file-backed pages. */
    if ((!data->is_mmap && data->writable) || !data->file)
    {
        /* Evict page into a swap slot. */
        data->swap_slot = swap_out (data->frame->addr);
        /* Panic the kernel if the swap slot is full. */
        if (data->swap_slot == BITMAP_ERROR) {
            PANIC ("Failed to swap out page during eviction");
        }
        data->swapped = true;
        data->frame = NULL;
        if (!cur_holds_data_lock) {
            lock_release(&data->lock);
        }

    }
    
    /* Case 2: Memory-mapped data segment pages. */
    else if (data->file && data->is_mmap)
    {
        /* No need to write back if the page is not dirty. */
        if (pagedir_are_any_dirty (&data->pages))
        {
            bool hold_lock = lock_held_by_current_thread (&filesys_lock);
            if (hold_lock) {
                lock_acquire (&filesys_lock);
            }  
            int written_bytes = file_write_at (data->file, data->frame->addr, data->read_bytes, data->offset);
            if (hold_lock) {
                lock_release (&filesys_lock);
            }
            if (data->read_bytes != (size_t) written_bytes)
            {
                PANIC ("Failed to write back memory mapped page during eviction");
            }
        }
        data->frame = NULL;
        if (!cur_holds_data_lock) {
            lock_release(&data->lock);
        }
    }
    return;
}

/* Chooses a frame to evict using the Clock algorithm. */
static struct frame *
frame_choose_victim(void) 
{
    struct frame *victim = NULL;

    /* If the clock hand is NULL, start from the beginning of the frame table. */
    if (clock_hand == NULL) {
        hash_first(&i, &frame_table);
        while (clock_hand == NULL) {
            hash_next(&i);
            clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
        }
    }
    int frame_count = hash_size(&frame_table);
    int scanned = 0;
    
    /* Iterate through the frame table until a victim is found. */
    while (scanned < TWO_CHANCES * frame_count) {
        struct list *pages = &clock_hand->data->pages;
        bool none_accessed = true;

        bool cur_holds_data_lock = lock_held_by_current_thread(&clock_hand->data->lock);

        if (!cur_holds_data_lock) {
            lock_acquire(&clock_hand->data->lock);
        }

        /* Iterate through the pages of the frame to see if any of them are accessed. */
        struct list_elem *e;
        for (e = list_begin(pages); e != list_end(pages); e = list_next(e)) {
            struct page *page = list_entry(e, struct page, data_elem);

            if (pagedir_is_accessed(page->owner->pagedir, page->vaddr)) {
                pagedir_set_accessed(page->owner->pagedir, page->vaddr, false);
                none_accessed = false;

                break;
            }
        }

        if (!cur_holds_data_lock) {
            lock_release(&clock_hand->data->lock);
        }

        /* If none of the pages are accessed, the frame is the victim. */
        if (none_accessed) {
            victim = clock_hand;
            goto found_victim;
        }

        /* Otherwise, move the clock hand to the next frame. */
        if (!hash_next(&i)) {
            hash_first(&i, &frame_table);
            hash_next(&i);
        }
        clock_hand = hash_entry(hash_cur(&i), struct frame, elem);
        
        /* Increment the number of frames scanned and continue to next iteration. */
        scanned++;
        continue;
    }
    
    found_victim:
    /* Panic if no victim is found after scanning all frames. */
    if (victim == NULL) {
        PANIC("Failed to find a victim frame during eviction");
    }

    /* Move the clock hand to the next frame in preparation for next eviction. */
    if (!hash_next(&i)) {
        hash_first(&i, &frame_table);
        hash_next(&i);
    }
    clock_hand = hash_entry(hash_cur(&i), struct frame, elem);

    return victim;
}

/* Frame table hash function. */
static unsigned
frame_hash(const struct hash_elem *elem, void *aux UNUSED) 
{
    const struct frame *f = hash_entry(elem, struct frame, elem);
    return hash_bytes(&f->addr, sizeof f->addr);
}

/* Frame table comparison function. */
static bool
frame_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) 
{
    const struct frame *f_a = hash_entry(a, struct frame, elem);
    const struct frame *f_b = hash_entry(b, struct frame, elem);
    return f_a->addr < f_b->addr;
}
