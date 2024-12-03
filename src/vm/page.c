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

/* Load a page into memory. */
void *
load_page(struct page *page) {
    struct page_data *data = page->data;

    /* Obtain a frame to store the page */
    void *frame = frame_alloc(PAL_USER, page->vaddr);
    if (frame == NULL) {
        PANIC("Out of memory: Frame allocation failed.");
    }

    /* Load the page into the frame */
    if (data->file != NULL) {
        lock_acquire(&filesys_lock);
        if (file_read_at(data->file, frame, data->read_bytes, data->offset) != (int) data->read_bytes) {
            frame_free(frame);
            lock_release(&filesys_lock);
            return NULL;
        }
        lock_release(&filesys_lock);
        memset(frame + data->read_bytes, 0, PGSIZE - data->read_bytes);
    } else if (data->swap_slot != (size_t) -1) {
        swap_in(frame, data->swap_slot);
        data->swap_slot = (size_t) -1;
    } else {
        memset(frame, 0, PGSIZE);
    }

    return frame;
}

/* Allocate a page. */
struct page *
page_alloc(void *vaddr, bool writable) {
    struct page *p = malloc(sizeof(struct page));
    if (p == NULL) {
        return NULL;
    }

    p->vaddr = vaddr;
    p->data = malloc(sizeof(struct page_data));
    if (p->data == NULL) {
        free(p);
        return NULL;
    }

    p->data->frame = NULL;
    p->data->file = NULL;
    p->data->ref_count = 1;
    p->data->writable = writable;
    p->data->is_mmap = false;
    p->data->swap_slot = (size_t) -1;

    hash_insert(&thread_current()->pg_table, &p->elem);

    return p;
}
