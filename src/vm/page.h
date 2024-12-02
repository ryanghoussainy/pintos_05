#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Page structure */
struct page {
    void *vaddr;            // User virtual page address.
    struct file *file;      // File associated with the page.
    uint32_t offset;        // Offset of the page in the file.
    uint32_t read_bytes;    // Number of bytes to read from the file.
    bool writable;          // Flag to indicate if the page is writable.
    struct hash_elem elem;  // List element for maintaining the supplemental page table as a linked list.
    bool is_mmap;           // Flag to indicate if the page is a memory mapped page.
    size_t swap_slot;       // Swap slot index for the page.
};

unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED);
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
struct page *supp_page_table_get(struct hash *hash, void *vaddr);
bool supp_page_table_insert(struct hash *hash, struct page *p);

#endif /* vm/page.h */