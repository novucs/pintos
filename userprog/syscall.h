#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void syscall_init (void);

struct child_process * retrieve_child_process (int pid);
void remove_child_process (struct child_process *cp);
struct child_process* add_child_process (int pid);
void clear_child_processes (void);
/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)
#endif /* userprog/syscall.h */

// Process statuses
#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2
