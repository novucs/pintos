#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "filesys/file.h"

#include "threads/thread.h"

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0           /* Successful execution. */
#define EXIT_FAILURE -1          /* Unsuccessful execution. */

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
struct child_process * process_add_child (int pid);
struct child_process * process_get_child (int pid);
void process_remove_child (struct child_process *cp);
void process_clear_children (void);
struct process_file * process_get_file_meta (int fd);
struct file * process_get_file (int fd);
void exit (int status);
void process_exit (void);
void process_activate (void);

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR -1

#endif /* userprog/process.h */
