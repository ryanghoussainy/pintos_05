#include "vm/page.h"

/* Page hash function */
unsigned
page_hash(const struct hash_elem *elem, void *aux UNUSED) {
    const struct page *p = hash_entry(elem, struct page, elem);
    return hash_bytes(&p->vaddr, sizeof p->vaddr);
}

/* Page comparison function */
bool
page_less(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED) {
    const struct page *p_a = hash_entry(a, struct page, elem);
    const struct page *p_b = hash_entry(b, struct page, elem);
    return p_a->vaddr < p_b->vaddr;
}
