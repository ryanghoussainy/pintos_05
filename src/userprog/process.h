#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define WORD_ALIGN_MASK ~(0x3)
#define NUM_ARGS 128

tid_t process_execute (const char *command);
struct o_file *get_o_file_from_fd(int fd);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
