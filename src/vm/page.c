#include "vm/page.h"

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
    // Ensure the hash table pointer is valid
    ASSERT(hash != NULL);
    ASSERT(vaddr != NULL);

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
