#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

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

/* Process identifier. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

/* Typical return values from main() and arguments to exit(). */
#define EXIT_SUCCESS 0           /* Successful execution. */
#define EXIT_FAILURE -1          /* Unsuccessful execution. */

/* Control values for exec() */
#define NOT_LOADED 0 //
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2

#define ARG_CODE 0
#define ARG_1 4
#define ARG_2 8
#define ARG_3 12

/* Validation functions. */
static void validate_ptr (const void *vaddr);
static void validate_buffer (const void* buffer, unsigned size);

/* Utility functions. */
static uint32_t load_stack(struct intr_frame *f, int offset);
static struct file * process_get_file (int fd);
static void exit (int status);
static int retrieve_virtual_address(const void *phys_addr);
static struct child_process * retrieve_child_process (int pid);

/* System call functions. */
static void syscall_handler (struct intr_frame *f);
static void handle_halt (struct intr_frame *f UNUSED);
static void handle_exit (struct intr_frame *f);
static void handle_exec (struct intr_frame *f);
static void handle_wait (struct intr_frame *f UNUSED);
static void handle_create (struct intr_frame *f);
static void handle_remove (struct intr_frame *f);
static void handle_open (struct intr_frame *f);
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

static uint32_t
load_stack(struct intr_frame *f, int offset)
{
  validate_ptr (f->esp + offset);
  return *((uint32_t*)(f->esp + offset));
}

/* Calls is_user_vaddr() from threads/vaddr.h to check address is valid
   and calls exit() with a PID_ERROR if not. */
void
validate_ptr (const void *vaddr)
{
  if (!is_user_vaddr(vaddr))
    exit (PID_ERROR);
}

/* Checks the pointer addresses to args on stack are valid. */
void
validate_buffer (const void* buffer, size_t size)
{
  for (size_t i = 0; i < size; i++)
    {
      validate_ptr (buffer);
      buffer++;
    }
}

/* Returns the kernel virtual address
   corresponding to the user process' physical address */
int
retrieve_virtual_address(const void *phys_addr)
{
  validate_ptr (phys_addr);
  void *ptr = pagedir_get_page (thread_current ()->pagedir, phys_addr);

  if (!ptr)
    exit (PID_ERROR);

  return (int) ptr;
}

/* Searches for and returns the child process with the id of the integer passed
  in making use of list functions from list.c which return the head, tail and
  next element. */
struct child_process *
retrieve_child_process (int pid)
{
  struct process_info *info = thread_current ()->process_info;
  struct list_elem *e;

  for (e = list_begin (&info->child_list);
       e != list_end (&info->child_list);
       e = list_next (e))
    {
      struct child_process *process = list_entry (e, struct child_process, elem);
      if (pid == process->id)
	      return process;
    }

  return NULL;
}

/* Searches for and returns the file with the id of the integer passed
   in making use of list functions from list.c which return the head, tail and
   next element. */
struct file*
process_get_file (int fd)
{
  struct process_info *info = thread_current ()->process_info;
  struct list_elem *e;

  for (e = list_begin (&info->file_list);
       e != list_end (&info->file_list);
       e = list_next (e))
    {
      struct process_file *file = list_entry (e, struct process_file, elem);

      if (fd == file->fd)
        return file->file;
    }

  return NULL;
}

static void
syscall_handler (struct intr_frame *f)
{
  int code = (int) load_stack (f, ARG_CODE);
  syscall_handlers[code] (f);
}

/* Terminates Pintos by calling shutdown_power_off() */
static void
handle_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status to the kernel.
   If the process's parent waits for it (see below), this is the status
   that will be returned. Conventionally, a status of 0 indicates success
   and nonzero values indicate errors. */
static void
handle_exit (struct intr_frame *f)
{
  int status = (int) load_stack (f, ARG_1);
  exit (status);
}

static void
exit (int status)
{
  struct thread * current = thread_current ();
  current->process_info->exit_status = status;
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line, passing any
   given arguments, nd returns the new process's program id (pid). Must
   return pid -1, which otherwise should not be a valid pid, if the program
   cannot load or run for any reason. Thus, the parent process cannot return
   from the exec until it knows whether the child process successfully loaded
   its executable. You must use appropriate synchronization to ensure this. */
static void
handle_exec (struct intr_frame *f)
{
  char *buffer = (char *) load_stack (f, ARG_1);

  pid_t pid = process_execute (buffer);
  struct child_process* process = retrieve_child_process (pid);
  ASSERT (process != NULL);

  while (process->load == NOT_LOADED)
    barrier ();

  if (process->load == LOAD_FAIL) {
    f->eax = PID_ERROR;
  } else
    f->eax = pid;
}

/* Waits for a child process pid and retrieves the child's exit status. */
static void
handle_wait (struct intr_frame *f UNUSED)
{
  printf ("handle_wait\n");
}

/* Creates a new file called file initially initial_size bytes in size.
   Returns true if successful, false otherwise. Creating a new file does
   not open it: opening the new file is a separate operation which would
   require a open system call. */
static void
handle_create (struct intr_frame *f UNUSED)
{
  const char *file_name = (const char *) load_stack (f, ARG_1);
  off_t initial_size = (off_t) load_stack (f, ARG_2);
  bool success = filesys_create (file_name, initial_size);
  f->eax = success;
}

/* Deletes the file called file. Returns true if successful, false otherwise.
   A file may be removed regardless of whether it is open or closed, and
   removing an open file does not close it. */
static void
handle_remove (struct intr_frame *f UNUSED)
{
  const char *file_name = (const char *) load_stack (f, ARG_1);
  bool success = filesys_remove (file_name);
  f->eax = success;
}

/* Opens the file called file. Returns a nonnegative integer handle called a
  "file descriptor" (fd), or -1 if the file could not be opened.
  File descriptors numbered 0 and 1 are reserved for the console:
    fd 0 (STDIN_FILENO) is standard input,
    fd 1 (STDOUT_FILENO) is standard output.
  The open system call will never return either of these file descriptors. */
static void
handle_open (struct intr_frame *f)
{
  const char *file_name = (const char *) load_stack (f, ARG_1);
  struct file *file = filesys_open (file_name);

  /* File open was denied, return failure. */
  if (file == NULL)
    {
      f->eax = EXIT_FAILURE;
      return;
    }

  /* Create a new file descriptor. */
  struct process_info *info = thread_current ()->process_info;
  struct process_file *pf = malloc (sizeof (struct process_file));

  pf->fd = ++(info->last_fd);
  pf->file = file;

  list_push_back (&info->file_list, &pf->elem);

  /* Return file descriptor ID. */
  f->eax = pf->fd;
}

/* Returns the size, in bytes, of the file open as fd. */
static void
handle_filesize (struct intr_frame *f UNUSED)
{
  int fd = (int) load_stack (f, ARG_1);
  struct file *file = process_get_file (fd);

  /* Return -1 if file descriptor invalid. */
  if (file == NULL)
    {
      f->eax = EXIT_FAILURE;
      return;
    }

  /* Return size of open file, in bytes. */
  int bytes = file_length (file);
  f->eax = bytes;
}

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read (due to a condition other
   than end of file). Fd 0 reads from the keyboard using input_getc(). */
static void
handle_read (struct intr_frame *f UNUSED)
{
  int fd = (int) load_stack (f, ARG_1);
  char *buffer = (char *) load_stack (f, ARG_2);
  size_t size = (int) load_stack (f, ARG_3);

  validate_buffer (buffer, size);

  if (fd == STDIN_FILENO)
    {
      for (size_t i = 0; i < size; i++)
        *(buffer + i) = input_getc();
      f->eax = size;
      return;
    }

  struct file *file = process_get_file (fd);

  if (file == NULL)
    {
      f->eax = EXIT_FAILURE;
      return;
    }

  int bytes = file_read (file, buffer, size);
  f->eax = bytes;
}

/* Writes size bytes from buffer to the open file fd. Returns the
   number of bytes actually written, which may be less than size if
   some bytes could not be written. */
static void
handle_write (struct intr_frame *f)
{
  int fd = (int) load_stack (f, ARG_1);
  const void *buffer = (void *) load_stack (f, ARG_2);
  size_t size = (size_t) load_stack (f, ARG_3);

  validate_buffer (buffer, size);

  if (fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      f->eax = size;
      return;
    }

  struct file *file = process_get_file (fd);

  if (file == NULL)
    {
      f->eax = EXIT_FAILURE;
      return;
    }

  int bytes = file_write (file, buffer, size);
  f->eax = bytes;
}

/* Changes the next byte to be read or written in open file fd to position,
   expressed in bytes from the beginning of the file.
   (Thus, a position of 0 is the file's start.) */
static void
handle_seek (struct intr_frame *f UNUSED)
{
  int fd = (int) load_stack(f, ARG_1);
  int position = (int) load_stack(f, ARG_2);
  struct file *file = process_get_file (fd);

  /* Do nothing if given invalid file descriptor. */
  if (file == NULL)
    return;

  /* Seek position in file. */
  file_seek (file, position);
}

/* Returns the position of the next byte to be read or written in open file fd,
   expressed in bytes from the beginning of the file. */
static void
handle_tell (struct intr_frame *f UNUSED)
{
  printf ("handle_tell\n");
}

/* Closes file descriptor fd. Exiting or terminating a process implicitly
   closes all its open file descriptors, as if by calling this function
   for each one. */
static void
handle_close (struct intr_frame *f UNUSED)
{
  printf ("handle_close\n");
}

/* ---------------------------------------------------------

                    NON-USERPROG SYSTEM CALLS

   --------------------------------------------------------- */

static void
handle_mmap (struct intr_frame *f UNUSED)
{
  printf ("handle_mmap\n");
}

static void
handle_munmap (struct intr_frame *f UNUSED)
{
  printf ("handle_munmap\n");
}

static void
handle_chdir (struct intr_frame *f UNUSED)
{
  printf ("handle_chdir\n");
}

static void
handle_mkdir (struct intr_frame *f UNUSED)
{
  printf ("handle_mkdir\n");
}

static void
handle_readdir (struct intr_frame *f UNUSED)
{
  printf ("handle_readdir\n");
}

static void
handle_isdir (struct intr_frame *f UNUSED)
{
  printf ("handle_isdir\n");
}

static void
handle_inumber (struct intr_frame *f UNUSED)
{
  printf ("handle_inumber\n");
}
