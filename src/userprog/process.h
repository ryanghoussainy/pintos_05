#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Word align mask for rounding down to the nearest multiple
   of 4 when setting up the stack. */
#define WORD_ALIGN_MASK ~(0x3)

/* Maximum number of arguments that can be passed to a process. */
#define MAX_ARGS 128

/* Lowest fd number that can be assigned to a file descriptor. */
#define BASE_FD 2

/* Maximum size, in pages, that the stack can dynamically grow to.
   8MiB GNU standard from pintos spec. */
#define STACK_MAX_SIZE 2048

tid_t process_execute (const char *command);
struct o_file *get_o_file_from_fd(int fd);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool frame_alloc_stack(void *esp, void* faddr);
bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
