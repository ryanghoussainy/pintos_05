#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Page structure */
struct page {
    void *vaddr;            // User virtual page address.
    struct page_data *data; // Page data.
    struct hash_elem elem;  // List element for maintaining the supplemental page table as a linked list.
};

/* Page data */
struct page_data {
    struct frame *frame;    // Frame associated with the page.
    struct file *file;      // File associated with the page.
    uint32_t offset;        // Offset of the page in the file.
    uint32_t read_bytes;    // Number of bytes to read from the file.
    int ref_count;          // Reference count for the page.
    bool writable;          // Flag to indicate if the page is writable.
    bool is_mmap;           // Flag to indicate if the page is a memory mapped page.
    size_t swap_slot;       // Swap slot index for the page.
};

unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED);
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
struct page *supp_page_table_get(struct hash *hash, void *vaddr);
bool supp_page_table_insert(struct hash *hash, struct page *p);

void *load_page(struct page *p);
struct page *page_alloc(void *vaddr, bool writable);

#endif /* vm/page.h */