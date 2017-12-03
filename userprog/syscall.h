#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>

#include "devices/shutdown.h"
#include "devices/input.h"

#include "filesys/file.h"
#include "filesys/filesys.h"

#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "userprog/pagedir.h"
#include "userprog/process.h"

#define DEBUG_MODE

void syscall_init (void);

#define MAX_ARGS 3
#define USER_VADDR_BOTTOM ((void *) 0x08048000)

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0          /* Successful execution. */
#define EXIT_FAILURE 1          /* Unsuccessful execution. */

// Control values for exec()
#define NOT_LOADED 0 //
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2

#endif /* userprog/syscall.h */
