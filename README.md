# PintOS

This projects consists of 4 parts:
1. Alarm Clock
2. Scheduling
3. User Programs
4. Virtual Memory


## Alarm Clock

- Stop busy-waiting - implemented the `timer_sleep()` function to use synchronisation methods between threads.

## Scheduling

- Priority donation - allowing threads to donate their priorities when they are waiting on a lock.
- Priority scheduling - ensuring that the highest priority thread is always running and that the highest priority sleeping thread is awoken first in the context of synchronisation primitives.
- Advanced scheduler - to ensure "fairness" between threads, which includes a "niceness" value for threads as well as measures to ensure that a high priority thread does not run for too long.

## User Programs

- Argument passing - ensuring arguments are parsed and passed onto the thread start-up section.
- Stack set-up - upon thread creation, load arguments into the stack.
- System calls
- Process waiting - used a structure to link a process to its children, allowing one to wait for the other.
- Deny writes to executible files

## Virtual Memory

- Supplemental page table - each process uses its SPT so as not to immediately load the page into memory, but instead to store its metadata and lazy load it later.
- Page fault handler - determine cause of page fault and load pages into memory if necessary.
- Stack growth - grow the stack if the page fault address is deemed likely to be stack access.
- Memory-mapped files
- Page sharing
- Page reclamation
- Frame eviction - when failing to allocate a frame, we evict a selected frame using the Second Chance algorithm.
