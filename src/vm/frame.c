#include "vm/frame.h"
#include "vm/page.h"

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

void *
frame_alloc(enum palloc_flags pal, uint8_t *page) {
    struct thread *cur = thread_current();

    void *frame = palloc_get_page(pal);
    if (frame == NULL) {
        // No free frames, implement eviction (Task 3 will cover eviction logic).
        PANIC("Out of memory: frame table allocator failed");
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
    palloc_free_page(f_entry->addr);
    free(f_entry);

    lock_release(&frame_lock);
}

