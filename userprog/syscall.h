#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void syscall_init (void);

#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2

#endif /* userprog/syscall.h */
