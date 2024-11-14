#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdlib.h>
#include <lib/kernel/hash.h> 
#include <threads/interrupt.h>

#define CONSOLE_INCR 400

/* Lock used when handling accessing the file system to ensure synchronisation. */
struct lock filesys_lock;

typedef int pid_t;
typedef void (*syscall_func_t)(struct intr_frame *f);

#define ARG_STEP 4

#define ret_address(x) (x)
#define get_arg_1(x) ((x) + ARG_STEP)
#define get_arg_2(x) ((x) + (2 * ARG_STEP))
#define get_arg_3(x) ((x) + (3 * ARG_STEP))

/*
 * Contains a file opened by a process.
 */
struct o_file {
    int fd;                     /* The file descriptor */
    struct file *file;          /* Contents of loaded file */
    struct hash_elem fd_elem;   /* To put open files in a hash table of the process */
};

void syscall_init (void);
void exit(int status);  

#endif /* userprog/syscall.h */
