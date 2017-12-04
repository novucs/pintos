#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
struct child_process * process_add_child (int pid);
struct child_process * process_get_child (int pid);
void process_remove_child (struct child_process *cp);
void process_clear_children (void);
struct file * process_get_file (int fd);
void process_exit (void);
void process_activate (void);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR -1

#endif /* userprog/process.h */
