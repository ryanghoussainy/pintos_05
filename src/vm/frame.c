#include "vm/frame.h"

void frame__table_init(void) {
    list_init(&frame_table);
    lock_init(&frame_lock);
}

void *frame_alloc(struct page *page) {
    lock_acquire(&frame_lock);

    void *frame = palloc_get_page(PAL_USER);
    if (frame == NULL) {
        // No free frames, implement eviction (Task 3 will cover eviction logic).
        PANIC("Out of memory: frame table allocator failed");
    }

    // Allocate frame table entry.
    struct frame *f = malloc(sizeof(struct frame));
    if (f == NULL) {
        palloc_free_page(frame);
        lock_release(&frame_lock);
        PANIC("Out of memory: frame table entry allocation failed");
    }

    f->frame_addr = frame;
    f->page = page;
    f->owner = thread_current();
    f->pinned = false;

    list_push_back(&frame_table, &f->elem);
    lock_release(&frame_lock);

    return frame;
}

void frame_free(void *frame_addr) {
    lock_acquire(&frame_lock);

    struct list_elem *e;
    for (e = list_begin(&frame_table); e != list_end(&frame_table); e = list_next(e)) {
        struct frame *f = list_entry(e, struct frame, elem);
        if (f->frame_addr == frame_addr) {
            list_remove(e);
            palloc_free_page(frame_addr);
            free(f);
            break;
        }
    }

    lock_release(&frame_lock);
}

