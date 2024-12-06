#include "vm/page.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "filesys/file.h"
#include "devices/swap.h"
#include <string.h>
#include "lib/kernel/bitmap.h"

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
spt_get(struct hash *hash, void *vaddr)
{
    /* Align the virtual address to the nearest page boundary. */
    vaddr = pg_round_down(vaddr);

    /* Create a temporary struct page to use as a lookup key. */
    struct page entry;
    entry.vaddr = vaddr;

    /* Search for the corresponding page in the hash table. */
    struct hash_elem *found = hash_find(hash, &entry.elem);
    if (found == NULL) {
        /* No matching entry found, return NULL. */
        return NULL;
    }

    /* Extract and return the full struct page from the hash element. */
    return hash_entry(found, struct page, elem);
}

/* Insert a page into the supplemental page table. */
bool
spt_insert(struct hash *hash, struct page *p)
{
  struct hash_elem *found = hash_insert(hash, &p->elem);
  return found == NULL;
}

/* Load a page into a frame, returning the frame. */
struct frame *
load_page(struct page *page) {
    struct shared_data *data = page->data;

    /* Obtain a frame to store the page */
    struct frame *frame = frame_alloc(data);
    data->frame = frame;
    void *frame_addr = data->frame->addr;
    if (frame_addr == NULL) {
        PANIC("Out of memory: Frame allocation failed.");
    }

    /* Pin the frame. */
    // lock_acquire(&frame_lock);
    // page->data->frame->pinned = true;
    // lock_release(&frame_lock);

    /* Check if the current thread holds the file system lock */
    bool cur_holds_filesys = lock_held_by_current_thread(&filesys_lock);

    /* Load the page into the frame */
    if (data->swapped) {
        swap_in(frame_addr, data->swap_slot);
        struct list_elem *elem;
        for (elem = list_begin (&data->pages); elem != list_end (&data->pages); elem = list_next (elem))
            {
                struct page *page = list_entry (elem, struct page, data_elem);
                pagedir_set_dirty (page->owner->pagedir, page->vaddr, true);
            }
        data->swapped = false;
    } 
    if (data->file != NULL) {
        if (!cur_holds_filesys) 
            lock_acquire(&filesys_lock);

        if (file_read_at(data->file, frame_addr, data->read_bytes, data->offset) != (int) data->read_bytes) {
            frame_free(data->frame);
            if (!cur_holds_filesys)
                lock_release(&filesys_lock);
            return NULL;
        }
        if (!cur_holds_filesys)
            lock_release(&filesys_lock);
            
        memset(frame_addr + data->read_bytes, 0, PGSIZE - data->read_bytes);
    } else {
        memset(frame_addr, 0, PGSIZE);
    }

    /* Pin the frame. */
    // lock_acquire(&frame_lock);
    // page->data->frame->pinned = true;
    // lock_release(&frame_lock);

    /* Find the corresponding frame in the frame table. */
    // lock_acquire(&frame_lock);
    // struct frame f_temp;
    // f_temp.addr = frame_addr;
    // struct hash_elem *e = hash_find(&frame_table, &f_temp.elem);
    // if (e == NULL) {
    //     lock_release(&frame_lock);
    //     PANIC("Frame not found in frame table after allocation");
    // }
    // struct frame *f = hash_entry(e, struct frame, elem);
    // data->frame = f;
    // lock_release(&frame_lock);

    return frame;
}

/* Returns a copy of shared page data. */
struct shared_data *
copy_shared_data(struct page *page) {
    /* Allocate shared data */
    struct shared_data *new_data = malloc(sizeof(struct shared_data));
    if (new_data == NULL) {
        return NULL;
    }

    /* Copy shared data */
    new_data->frame = NULL;
    new_data->file = page->data->file;
    new_data->offset = page->data->offset;
    new_data->read_bytes = page->data->read_bytes;
    new_data->writable = page->data->writable;
    new_data->is_mmap = page->data->is_mmap;
    new_data->swap_slot = (size_t) -1;
    list_init(&new_data->pages);
    lock_init(&new_data->lock);

    /* Remove the found page from the list of pages in the old shared data. */
    lock_acquire(&page->data->lock);
    list_remove(&page->data_elem);
    lock_release(&page->data->lock);

    /* Add page to new shared data. */
    lock_acquire(&new_data->lock);
    list_push_back(&new_data->pages, &page->data_elem);
    lock_release(&new_data->lock);

    return new_data;
}

/* Create a page structure. Add it to the current thread's SPT. */
struct page *
page_create(void *vaddr, bool writable) {
    struct page *p = page_alloc(vaddr, writable);
    if (p == NULL) {
        return NULL;
    }
    struct thread *cur = thread_current();
    if (!spt_insert(&cur->spt, p)) {
        free(p);
        return NULL;
    }
    return p;
}

/* Allocate a page, returning the page. */
struct page *
page_alloc(void *vaddr, bool writable) {
    /* Allocate memory a new page struct. */
    struct page *p = malloc(sizeof(struct page));
    if (p == NULL) {
        return NULL;
    }
    struct thread *cur = thread_current();

    /* Initialise the page struct. */
    p->vaddr = vaddr;
    p->owner = cur;
    p->data = malloc(sizeof(struct shared_data));
    if (p->data == NULL) {
        free(p);
        return NULL;
    }

    /* Initialise the metadata of page struct. */
    p->data->frame = NULL;
    p->data->file = NULL;
    p->data->writable = writable;
    p->data->is_mmap = false;
    p->data->swap_slot = 0;
    p->data->swapped = false;
    list_init(&p->data->pages);
    lock_init(&p->data->lock);
    lock_acquire(&p->data->lock);
    list_push_back(&p->data->pages, &p->data_elem);
    lock_release(&p->data->lock);

    return p;
}

/* Pins a collection of user pages (buffer) */
// bool
// pin_user_pages(void *buffer, size_t size) {
//     void *upage = pg_round_down(buffer);
//     void *end = buffer + size;

//     while (upage < end) {
//         if (!pin_frame(upage)) {
//             return false;
//         }
//         upage += PGSIZE;
//     }

//     return true;
// }

// /* Unpins a collection of user pages (buffer) */
// void
// unpin_user_pages(void *buffer, size_t size) {
//     void *upage = pg_round_down(buffer);
//     void *end = buffer + size;

//     while (upage < end) {
//         unpin_frame(upage);
//         upage += PGSIZE;
//     }
// }

bool
check_user_pages_writable(void* buffer, size_t size) {
    void *upage = pg_round_down(buffer);
    void *end = buffer + size;
    struct thread *cur = thread_current();

    while (upage < end) {
        struct page *page = spt_get(&cur->spt, upage);
        if (page != NULL && !page->data->writable) {
            return false;
        }
        upage += PGSIZE;
    }

    return true;
}