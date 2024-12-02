#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include <stdlib.h>
#include <lib/kernel/hash.h> 
#include <threads/interrupt.h>

/* Maximum chunk size of data that can be written to the console. */
#define CONSOLE_INCR 400

/* The maximum number of open files a process can have */
#define MAX_OFILES 128

/* Exit status when an error is encountered during syscall. */
#define STATUS_ERR (-1)

/* Return value for unsuccessful syscall. */
#define RETURN_ERR (-1)

/* Lock used when handling accessing the file system to ensure synchronisation. */
struct lock filesys_lock;

typedef int pid_t;
typedef void (*syscall_func_t)(struct intr_frame *f);

/* Defintions for retrieivng return address and arguments from stack frame. */
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

/*
 * Contains a memory mapped file.
 */
struct mapid_file {
    int mapid;                  /* The mapid */
    struct file *file;          /* Contents of loaded file */
    struct hash_elem mapid_elem;/* To put open files in a hash table of the process */
};

void syscall_init (void);
void munmap(int mapid);
void exit(int status);
unsigned mmap_hash(const struct hash_elem *e, void *aux);
bool mmap_less(const struct hash_elem *a, const struct hash_elem *b, void *aux);  

#endif /* userprog/syscall.h */
