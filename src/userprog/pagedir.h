#ifndef USERPROG_PAGEDIR_H
#define USERPROG_PAGEDIR_H

#include <stdbool.h>
#include <stdint.h>
#include "lib/kernel/list.h"

uint32_t *pagedir_create (void);
void pagedir_destroy (uint32_t *pd);
bool pagedir_set_page (uint32_t *pd, void *upage, void *kpage, bool rw);
void *pagedir_get_page (uint32_t *pd, const void *upage);
void pagedir_clear_page (uint32_t *pd, void *upage);
bool pagedir_is_dirty (uint32_t *pd, const void *upage);
void pagedir_set_dirty (uint32_t *pd, const void *upage, bool dirty);
bool pagedir_is_accessed (uint32_t *pd, const void *upage);
void pagedir_set_accessed (uint32_t *pd, const void *upage, bool accessed);
bool pagedir_is_writable (uint32_t *pd, const void *upage);
void pagedir_set_writable (uint32_t *pd, const void *upage, bool writable);
void pagedir_activate (uint32_t *pd);
bool pagedir_any_dirty (struct list *pages);

#endif /* userprog/pagedir.h */
