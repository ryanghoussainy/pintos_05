#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "hash.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* Page structure */
struct page {
    void *vaddr;                /* User virtual page address. */
    struct thread *owner;       /* Thread owning the page. */
    struct shared_data *data;   /* Page data. */
    struct hash_elem elem;      /* List element for maintaining the supplemental page table as a linked list. */
    struct list_elem data_elem; /* List element for maintaining the frame's list of pages. */
};

/* Shared data */
struct shared_data {
    struct frame *frame;    /* Frame associated with the page. */
    struct file *file;      /* File associated with the page. */
    uint32_t offset;        /* Offset of the page in the file. */
    uint32_t read_bytes;    /* Number of bytes to read from the file. */
    bool writable;          /* Flag to indicate if the page is writable. */
    bool is_mmap;           /* Flag to indicate if the page is a memory mapped page. */
    size_t swap_slot;       /* Swap slot index for the page. */
    struct list pages;      /* List of pages. */
    struct lock lock;       /* Lock for synchronizing page access. */
};

unsigned page_hash(const struct hash_elem *elem, void *aux UNUSED);
bool page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
struct page *supp_page_table_get(struct hash *hash, void *vaddr);
bool supp_page_table_insert(struct hash *hash, struct page *p);

bool pin_user_pages(void *buffer, size_t size);
void unpin_user_pages(void *buffer, size_t size);

bool check_user_pages_writable(void* buffer, size_t size);

struct frame *load_page(struct page *p);
struct page *page_alloc(void *vaddr, bool writable);

#endif /* vm/page.h */
