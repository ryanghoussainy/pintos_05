#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdlib.h>
#include <lib/kernel/hash.h> 

#define CONSOLE_INCR 400

/*
 * Contains a file opened by a process.
 */
struct o_file {
    int fd;                     /* The file descriptor */
    struct file *file;          /* Contents of loaded file */
    struct hash_elem fd_elem;   /* To put open files in a hash table of the process */
};

void syscall_init (void);

void sys_halt (void);
void sys_exit (int status);
int sys_write (int fd, const void *buffer, unsigned size);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);

#endif /* userprog/syscall.h */
