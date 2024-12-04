#include "vm/page.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "devices/swap.h"
#include <string.h>

/* Page hash function. */
unsigned
page_hash(const struct hash_elem *elem, void *aux UNUSED) {
    const struct page *p = hash_entry(elem, struct page, elem);
    return hash_bytes(&p->vaddr, sizeof p->vaddr);
}

/* Page comparison function. */
bool
page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct page *p_a = hash_entry(a, struct page, elem);
    const struct page *p_b = hash_entry(b, struct page, elem);
    return p_a->vaddr < p_b->vaddr;
}

/* Get a page from the supplemental page table. */
struct page * 
supp_page_table_get(struct hash *hash, void *vaddr)
{
    // Align the virtual address to the nearest page boundary
    vaddr = pg_round_down(vaddr);

    // Create a temporary struct page to use as a lookup key
    struct page entry;
    entry.vaddr = vaddr;

    // Search for the corresponding page in the hash table
    struct hash_elem *found = hash_find(hash, &entry.elem);
    if (found == NULL) {
        // No matching entry found, return NULL
        return NULL;
    }

    // Extract and return the full struct page from the hash element
    return hash_entry(found, struct page, elem);
}

/* Insert a page into the supplemental page table. */
bool
supp_page_table_insert(struct hash *hash, struct page *p)
{
  struct hash_elem *found = hash_insert(hash, &p->elem);
  return found == NULL;
}

/* Load a page into a frame. */
struct frame *
load_page(struct page *page) {
    struct shared_data *data = page->data;

    /* Obtain a frame to store the page */
    struct frame *frame = frame_alloc(page);
    void *frame_addr = frame->addr;

    if (frame_addr == NULL) {
        PANIC("Out of memory: Frame allocation failed.");
    }

    bool cur_holds_filesys = lock_held_by_current_thread(&filesys_lock);

    /* Load the page into the frame */
    if (data->file != NULL) {
        if (!cur_holds_filesys) 
            lock_acquire(&filesys_lock);

        if (file_read_at(data->file, frame_addr, data->read_bytes, data->offset) != (int) data->read_bytes) {
            frame_free(frame);
            if (!cur_holds_filesys)
                lock_release(&filesys_lock);
            return NULL;
        }
        if (!cur_holds_filesys)
            lock_release(&filesys_lock);
            
        memset(frame_addr + data->read_bytes, 0, PGSIZE - data->read_bytes);
    } else if (data->swap_slot != (size_t) -1) {
        swap_in(frame_addr, data->swap_slot);
        data->swap_slot = (size_t) -1;
    } else {
        memset(frame_addr, 0, PGSIZE);
    }

    /* Update data->frame to point to the frame struct */
    lock_acquire(&frame_lock);
    struct frame f_temp;
    f_temp.addr = frame_addr;
    struct hash_elem *e = hash_find(&frame_table, &f_temp.elem);
    if (e == NULL) {
        lock_release(&frame_lock);
        PANIC("Frame not found in frame table after allocation");
    }
    struct frame *f = hash_entry(e, struct frame, elem);
    data->frame = f;
    lock_release(&frame_lock);

    return frame;
}

/* Allocate a page. */
struct page *
page_alloc(void *vaddr, bool writable) {
    struct page *p = malloc(sizeof(struct page));
    if (p == NULL) {
        return NULL;
    }

    struct thread *cur = thread_current();

    p->vaddr = vaddr;
    p->owner = cur;
    p->data = malloc(sizeof(struct shared_data));
    if (p->data == NULL) {
        free(p);
        return NULL;
    }

    p->data->frame = NULL;
    p->data->file = NULL;
    p->data->writable = writable;
    p->data->is_mmap = false;
    p->data->swap_slot = (size_t) -1;
    list_init(&p->data->pages);
    lock_init(&p->data->lock);
    
    lock_acquire(&p->data->lock);
    list_push_back(&p->data->pages, &p->data_elem);
    lock_release(&p->data->lock);

    hash_insert(&cur->pg_table, &p->elem);

    return p;
}
