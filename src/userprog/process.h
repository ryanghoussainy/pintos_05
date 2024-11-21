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

tid_t process_execute (const char *command);
struct o_file *get_o_file_from_fd(int fd);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */
