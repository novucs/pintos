#include "userprog/syscall.h"

static void syscall_handler (struct intr_frame *);

// Main syscall functions
void syscall_init (void);
void halt (void) NO_RETURN;
void exit (int status) NO_RETURN;
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);


// Validation functions
void validate_ptr (const void *vaddr);
void validate_buffer (void* buffer, unsigned size);

// Utility functions
int retrieve_virtual_address(const void *phys_addr);
struct file* process_get_file (int fd);
// Retrieval functions
void retrieve_args (struct intr_frame *f, int *arg, int n);

struct p_child* retrieve_p_child (int pid);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f)
{
  uint32_t *p=f->esp; // get the syscall number, which is defined in ‘Pintos/lib/syscall-nr.h’)
  int arg[MAX_ARGS];

  switch(*p) {

    case SYS_HALT: {
      #if defined(DEBUG_MODE)
      printf("\nSYS_HALT (%d)", *p);
      #endif // DEBUG_MODE

      halt();
      break;
    }

    case SYS_EXIT: {
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_EXIT (%d)", *p);
      #endif // DEBUG_MODE

      retrieve_args(f, &arg[0], 1);
    	exit(arg[0]);
    	break;
          } // end of SYS_EXIT

    case SYS_EXEC: {
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_EXEC (%d)", *p);
      #endif // DEBUG_MODE

      retrieve_args(f, &arg[0], 1);
      arg[0] = retrieve_virtual_address((const void *) arg[0]);
      f->eax = exec((const char *) arg[0]);
      break;
    }

    case SYS_WAIT:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_WAIT (%d)", *p);
      #endif // DEBUG_MODE

      retrieve_args(f, &arg[0], 1);
      f->eax = wait(arg[0]);
      break;
    }

    case SYS_CREATE:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_REMOVE:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_OPEN:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_FILESIZE:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_READ:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_WRITE:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_WRITE (%d)", *p);
      #endif // DEBUG_MODE

      retrieve_args(f, &arg[0], 3);
    	validate_buffer((void *) arg[1], (unsigned) arg[2]);
    	arg[1] = retrieve_virtual_address((const void *) arg[1]);
    	f->eax = write(arg[0], (const void *) arg[1],
    		       (unsigned) arg[2]);
      break;
    } // end of SYS_WRITE

    case SYS_SEEK:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_TELL:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    case SYS_CLOSE:{
      #if defined(DEBUG_MODE)
      printf("\n\nSYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
    }

    default:
      #if defined(DEBUG_MODE)
      printf("\n\nDefault: SYS_CALL (%d) not implemented", *p);
      #endif // DEBUG_MODE

      thread_exit();
      break;
  } // end of switch
}

// Terminates Pintos by calling shutdown_power_off()
void
halt() {
  #if defined(DEBUG_MODE)
  printf("\n(halt)");
  #endif // DEBUG_MODE
  shutdown_power_off();
}

/*  Terminates the current user program, returning status to the kernel.
    If the process's parent waits for it (see below), this is the status
    that will be returned. Conventionally, a status of 0 indicates success
    and nonzero values indicate errors.*/
void
exit(int status)
{
  //FIXME: Needs Implementing
}

/*Runs the executable whose name is given in cmd_line, passing any
given arguments, nd returns the new process's program id (pid). Must
return pid -1, which otherwise should not be a valid pid, if the program
cannot load or run for any reason. Thus, the parent process cannot return
from the exec until it knows whether the child process successfully loaded
its executable. You must use appropriate synchronization to ensure this.*/
pid_t
exec (const char *cmd_line)
{
  #if defined(DEBUG_MODE)
  printf("\n(exec)");
  #endif // DEBUG_MODE

  pid_t pid = process_execute(cmd_line);
  struct p_child* cp = retrieve_p_child(pid);
  ASSERT(cp);
  while (cp->load == NOT_LOADED)
  {
    barrier();
  }

  if (cp->load == LOAD_FAIL)
  {
    return PID_ERROR;
  }

  return pid;
}

// Waits for a child process pid and retrieves the child's exit status.
int
wait (pid_t pid)
{
  #if defined(DEBUG_MODE)
  printf("\n(wait)");
  #endif // DEBUG_MODE
  return process_wait(pid);
}

/*
  Creates a new file called file initially initial_size bytes in size.
  Returns true if successful, false otherwise. Creating a new file does
  not open it: opening the new file is a separate operation which would
  require a open system call.
*/
bool
create (const char *file, unsigned initial_size)
{
  //FIXME: Needs Implementing
}

/*
  Deletes the file called file. Returns true if successful, false otherwise.
  A file may be removed regardless of whether it is open or closed, and
  removing an open file does not close it
*/
bool
remove (const char *file)
{
  //FIXME: Needs Implementing
}

/*
Opens the file called file. Returns a nonnegative integer handle called a
"file descriptor" (fd), or -1 if the file could not be opened.
File descriptors numbered 0 and 1 are reserved for the console:
                      fd 0 (STDIN_FILENO) is standard input,
                      fd 1 (STDOUT_FILENO) is standard output.

The open system call will never return either of these file descriptors.
*/
int
open (const char *file)
{
  //FIXME: Needs Implementing
}

/*
Returns the size, in bytes, of the file open as fd.
*/
int
filesize (int fd)
{
  //FIXME: Needs Implementing
}

/*
  Reads size bytes from the file open as fd into buffer.
  Returns the number of bytes actually read (0 at end of file),
  or -1 if the file could not be read (due to a condition other
  than end of file). Fd 0 reads from the keyboard using input_getc().
*/
int
read (int fd, void *buffer, unsigned size)
{
  //FIXME: Needs Implementing
}

/*
  Writes size bytes from buffer to the open file fd. Returns the
  number of bytes actually written, which may be less than size if
  some bytes could not be written.
*/
int
write (int fd, const void *buffer, unsigned size)
{
  #if defined(DEBUG_MODE)
  printf("\n(write)");
  #endif // DEBUG_MODE
  if (fd == STDOUT_FILENO)
    {
      putbuf(buffer, size);
      return size;
    }
  lock_acquire(&filesys_lock);
  struct file *f = process_get_file(fd);
  if (!f)
    {
      lock_release(&filesys_lock);
      return PID_ERROR;
    }
  int bytes = file_write(f, buffer, size);
  lock_release(&filesys_lock);
  return bytes;
}

/*
  Changes the next byte to be read or written in open file fd to position,
  expressed in bytes from the beginning of the file.
  (Thus, a position of 0 is the file's start.)
*/
void
seek (int fd, unsigned position)
{
  //FIXME: Needs Implementing
}

/*
  Returns the position of the next byte to be read or written in open file fd,
  expressed in bytes from the beginning of the file.
*/
unsigned
tell (int fd)
{
  //FIXME: Needs Implementing
}

/*
  Closes file descriptor fd. Exiting or terminating a process implicitly
  closes all its open file descriptors, as if by calling this function
  for each one.
*/
void
close (int fd)
{
  //FIXME: Needs Implementing
}

/*
    Calls is_user_vaddr() from threads/vaddr.h to check address is valid
    and calls exit() with a PID_ERROR if not.
*/
void
validate_ptr (const void *vaddr)
{
  #if defined(DEBUG_MODE)
  printf("\n(validate_ptr)");
  #endif // DEBUG_MODE
  if (!is_user_vaddr(vaddr))
    {
      #if defined(DEBUG_MODE)
      printf("\n(validate_ptr): NOT VALID ADDRESS");
      #endif // DEBUG_MODE
      exit(PID_ERROR);
    }
}

// Checks the pointer addresses to args on stack are valid
void
validate_buffer (void* buffer, unsigned size)
{
  #if defined(DEBUG_MODE)
  printf("\n(validate_buffer)");
  #endif // DEBUG_MODE
  unsigned i;
  char* local_buffer = (char *) buffer;
  for (i = 0; i < size; i++)
    {
      validate_ptr((const void*) local_buffer);
      local_buffer++;
    }
}

/*
  Collects the args stored in the stack by using the addresses stored
  in the stack as the pointer
*/
void
retrieve_args (struct intr_frame *f, int *arg, int n)
{
  #if defined(DEBUG_MODE)
  printf("\n(retrieve_args)");
  #endif // DEBUG_MODE
  int i;
  int *ptr;
  for (i = 0; i < n; i++)
    {
      ptr = (int *) f->esp + i + 1;
      validate_ptr((const void *) ptr);
      arg[i] = *ptr;
    }
}


/*
  Returns the kernel virtual address
  corresponding to the user process' physical address
*/
int
retrieve_virtual_address(const void *phys_addr)
{
  #if defined(DEBUG_MODE)
  printf("\n(retrieve_virtual_address)");
  #endif // DEBUG_MODE
  validate_ptr(phys_addr);
  void *ptr = pagedir_get_page(thread_current()->pagedir, phys_addr);
  if (!ptr)
    {
      exit(PID_ERROR);
    }
  return (int) ptr;
}

/*
  Searches for and returns the child process with the id of the integer passed
  in making use of list functions from list.c which return the head, tail and
  next element.
*/
struct p_child*
retrieve_p_child (int pid)
{
  #if defined(DEBUG_MODE)
  printf("\n(retrieve_p_child)");
  #endif // DEBUG_MODE
  struct thread *cur = thread_current();
  struct list_elem *e;
  for (e = list_begin (&cur->child_list); e != list_end (&cur->child_list); e = list_next (e))
        {
          struct p_child *cp = list_entry (e, struct p_child, elem);
          if (pid == cp->pid)
      	    {
      	      return cp;
      	    }
        }
  return NULL;
}

/*
  Searches for and returns the file with the id of the integer passed
  in making use of list functions from list.c which return the head, tail and
  next element.
*/
struct file*
process_get_file (int fd)
{
  struct thread *t = thread_current();
  struct list_elem *e;

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);
       e = list_next (e))
        {
          struct process_file *pf = list_entry (e, struct process_file, elem);
          if (fd == pf->fd)
	    {
	      return pf->file;
	    }
        }
  return NULL;
}
