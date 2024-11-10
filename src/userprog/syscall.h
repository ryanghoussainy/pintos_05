#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdlib.h>
#include <lib/kernel/hash.h> 

#define CONSOLE_INCR 400

typedef int pid_t;

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
pid_t sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);

#endif /* userprog/syscall.h */
