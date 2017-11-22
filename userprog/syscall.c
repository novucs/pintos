#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define ARG_CODE 0
#define ARG_1 4
#define ARG_2 8
#define ARG_3 12

static uint32_t load_stack(struct intr_frame *f, int offset);
static void syscall_handler (struct intr_frame *f);
static void handle_halt (struct intr_frame *f UNUSED);
static void handle_exit (struct intr_frame *f);
static void handle_exec (struct intr_frame *f);
static void handle_wait (struct intr_frame *f);
static void handle_create (struct intr_frame *f);
static void handle_remove (struct intr_frame *f);
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

static struct file_descriptor
  {
    struct file *file;
    unsigned int id;
    struct list_elem elem;
    int pid;
  };

static struct list file_descriptors;
static int next_fd_id = 2;

void
syscall_init (void)
{
  list_init (&file_descriptors);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static uint32_t
load_stack (struct intr_frame *f, int offset)
{
  /* TODO: Add check for valid address. */
  return *((uint32_t*)(f->esp + offset));
}

static void
syscall_handler (struct intr_frame *f)
{
  /* TODO: @will - Validate the provided syscall code. */
  int code = (int) load_stack (f, ARG_CODE);
  syscall_handlers[code] (f);
}

static void
handle_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

static void
handle_exit (struct intr_frame *f)
{
  int status = (int) load_stack (f, ARG_1);
  struct thread *current = thread_current ();
  current->process_info->exit_status = status;
  thread_exit();
}

static void
handle_exec (struct intr_frame *f)
{
  char *buffer = (char *) load_stack (f, ARG_1);
  tid_t id = process_execute (buffer);
  f->eax = id;
}

static void
handle_wait (struct intr_frame *f)
{
  // TODO: Add safety checks as listed in Stanford documentation.
  tid_t id = (tid_t) load_stack (f, ARG_1);
  int exit_code = process_wait (id);
  f->eax = exit_code;
}

static void
handle_create (struct intr_frame *f)
{
  const char *file_name = (const char *) load_stack (f, ARG_1);
  off_t initial_size = (off_t) load_stack (f, ARG_2);
  bool success = filesys_create (file_name, initial_size);
  f->eax = success;
}

static void
handle_remove (struct intr_frame *f)
{
  const char *file_name = (const char *) load_stack (f, ARG_1);
  bool success = filesys_remove (file_name);
  f->eax = success;
}

static void
handle_open (struct intr_frame *f)
{
  const char *file_name = (const char *) load_stack (f, ARG_1);
  struct file *file = filesys_open (file_name);

  // File open was denied, return -1.
  if (file == NULL)
    {
      f->eax = -1;
      return;
    }

  // Create a new file descriptor.
  struct file_descriptor *fd = malloc (sizeof (struct file_descriptor));
  fd->file = file;
  fd->id = next_fd_id++;
  fd->pid = thread_current ()->process_info->pid;
  list_push_back (&file_descriptors, &fd->list_elem);

  // Return file descriptor ID.
  f->eax = fd->id;
}

static void
handle_filesize (struct intr_frame *f UNUSED)
{
  printf("handle_filesize\n");
}

static void
handle_read (struct intr_frame *f UNUSED)
{
  printf("handle_read\n");
}

static void
handle_write (struct intr_frame *f)
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

static void
handle_seek (struct intr_frame *f UNUSED)
{
  printf("handle_seek\n");
}

static void
handle_tell (struct intr_frame *f UNUSED)
{
  printf("handle_tell\n");
}

static void
handle_close (struct intr_frame *f UNUSED)
{
  printf("handle_close\n");
}

// -------------- IGNORE ALL SYSCALLS UNDER THIS LINE ---------------

static void
handle_mmap (struct intr_frame *f UNUSED)
{
  printf("handle_mmap\n");
}

static void
handle_munmap (struct intr_frame *f UNUSED)
{
  printf("handle_munmap\n");
}

static void
handle_chdir (struct intr_frame *f UNUSED)
{
  printf("handle_chdir\n");
}

static void
handle_mkdir (struct intr_frame *f UNUSED)
{
  printf("handle_mkdir\n");
}

static void
handle_readdir (struct intr_frame *f UNUSED)
{
  printf("handle_readdir\n");
}

static void
handle_isdir (struct intr_frame *f UNUSED)
{
  printf("handle_isdir\n");
}

static void
handle_inumber (struct intr_frame *f UNUSED)
{
  printf("handle_inumber\n");
}
