#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define ARG_CODE 0
#define ARG_1 4
#define ARG_2 8
#define ARG_3 12

static uint32_t load_stack(struct intr_frame *f, int offset);
static void syscall_handler (struct intr_frame *f UNUSED);
static void handle_halt (struct intr_frame *f UNUSED);
static void handle_exit (struct intr_frame *f);
static void handle_exec (struct intr_frame *f UNUSED);
static void handle_wait (struct intr_frame *f UNUSED);
static void handle_create (struct intr_frame *f UNUSED);
static void handle_remove (struct intr_frame *f UNUSED);
static void handle_open (struct intr_frame *f UNUSED);
static void handle_filesize (struct intr_frame *f UNUSED);
static void handle_read (struct intr_frame *f UNUSED);
static void handle_write (struct intr_frame *f);
static void handle_seek (struct intr_frame *f UNUSED);
static void handle_tell (struct intr_frame *f UNUSED);
static void handle_close (struct intr_frame *f UNUSED);
static void handle_mmap (struct intr_frame *f UNUSED);
static void handle_munmap (struct intr_frame *f UNUSED);
static void handle_chdir (struct intr_frame *f UNUSED);
static void handle_mkdir (struct intr_frame *f UNUSED);
static void handle_readdir (struct intr_frame *f UNUSED);
static void handle_isdir (struct intr_frame *f UNUSED);
static void handle_inumber (struct intr_frame *f UNUSED);

static void (*syscall_handlers[]) (struct intr_frame *f UNUSED) =
  {
    /* Projects 2 and later. */
    handle_halt,                   /* Halt the operating system. */
    handle_exit,                   /* Terminate this process. */
    handle_exec,                   /* Start another process. */
    handle_wait,                   /* Wait for a child process to die. */
    handle_create,                 /* Create a file. */
    handle_remove,                 /* Delete a file. */
    handle_open,                   /* Open a file. */
    handle_filesize,               /* Obtain a file's size. */
    handle_read,                   /* Read from a file. */
    handle_write,                  /* Write to a file. */
    handle_seek,                   /* Change position in a file. */
    handle_tell,                   /* Report current position in a file. */
    handle_close,                  /* Close a file. */

    /* Project 3 and optionally project 4. */
    handle_mmap,                   /* Map a file into memory. */
    handle_munmap,                 /* Remove a memory mapping. */

    /* Project 4 only. */
    handle_chdir,                  /* Change the current directory. */
    handle_mkdir,                  /* Create a directory. */
    handle_readdir,                /* Reads a directory entry. */
    handle_isdir,                  /* Tests if a fd represents a directory. */
    handle_inumber                 /* Returns the inode number for a fd. */
  };

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static uint32_t load_stack(struct intr_frame *f, int offset)
{
  /* TODO: Add check for valid address. */
  return *((uint32_t*)(f->esp + offset));
}

static void
syscall_handler (struct intr_frame *f)
{
  /* TODO: @will - Validate the provided syscall code. */
  int code = (int) load_stack(f, ARG_CODE);
  syscall_handlers[code] (f);
}

static void handle_halt (struct intr_frame *f UNUSED)
{
  printf("handle_halt\n");
}

static void handle_exit (struct intr_frame *f)
{
  int status = (int) load_stack(f, ARG_1);
  struct thread * current = thread_current();
  current->process_info->exit_status = status;
  thread_exit();
}

static void handle_exec (struct intr_frame *f UNUSED)
{
  printf("handle_exec\n");
}

static void handle_wait (struct intr_frame *f UNUSED)
{
  printf("handle_wait\n");
}

static void handle_create (struct intr_frame *f UNUSED)
{
  printf("handle_create\n");
}

static void handle_remove (struct intr_frame *f UNUSED)
{
  printf("handle_remove\n");
}

static void handle_open (struct intr_frame *f UNUSED)
{
  printf("handle_open\n");
}

static void handle_filesize (struct intr_frame *f UNUSED)
{
  printf("handle_filesize\n");
}

static void handle_read (struct intr_frame *f UNUSED)
{
  printf("handle_read\n");
}

static void handle_write (struct intr_frame *f)
{
  int fd = (int) load_stack(f, ARG_1);
  const void *buffer = (void *) load_stack(f, ARG_2);
  unsigned int length = (unsigned int) load_stack(f, ARG_3);

  /* TODO: @bgaster - Validate fd and buffer ptr. */

  if (fd == STDOUT_FILENO) {
    putbuf((const char *)buffer, (size_t)length);
  } else
    printf("handle_write does not support fd output\n");

  /* Set return value. */
  f->eax = length;
}

static void handle_seek (struct intr_frame *f UNUSED)
{
  printf("handle_seek\n");
}

static void handle_tell (struct intr_frame *f UNUSED)
{
  printf("handle_tell\n");
}

static void handle_close (struct intr_frame *f UNUSED)
{
  printf("handle_close\n");
}

static void handle_mmap (struct intr_frame *f UNUSED)
{
  printf("handle_mmap\n");
}

static void handle_munmap (struct intr_frame *f UNUSED)
{
  printf("handle_munmap\n");
}

static void handle_chdir (struct intr_frame *f UNUSED)
{
  printf("handle_chdir\n");
}

static void handle_mkdir (struct intr_frame *f UNUSED)
{
  printf("handle_mkdir\n");
}

static void handle_readdir (struct intr_frame *f UNUSED)
{
  printf("handle_readdir\n");
}

static void handle_isdir (struct intr_frame *f UNUSED)
{
  printf("handle_isdir\n");
}

static void handle_inumber (struct intr_frame *f UNUSED)
{
  printf("handle_inumber\n");
}
