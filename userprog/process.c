/*
 * AUTHORS
 * - William Randall 16002374 ( contact@novucs.net )
 * - Gareth Perry 16014980 ( gareth2.perry@uwe.ac.uk, garethnperry@gmail.com )
 * - Chris Taylor 16020794 ( christopherjamestaylor@outlook.com )
 */

#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "threads/malloc.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
static void free_process_info (struct thread *t);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  thread_current ()->holding_filesys_lock = true;
  lock_acquire (&filesys_lock);
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Extract the real file name from the command line. */
  char *save_ptr;
  char *real_name;
  real_name = strtok_r ((char *) file_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (real_name, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);

  struct child_process* child = process_get_child(tid);
  sema_down(&child->load_sema);
  lock_release (&filesys_lock);
  thread_current ()->holding_filesys_lock = false;

  if (child->status == PID_ERROR)
    return PID_ERROR;

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (file_name, &if_.eip, &if_.esp);
  struct thread *current_thread = thread_current ();

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success)
    {
      current_thread->process_info->exit_status = PID_ERROR;
      current_thread->child->status = PID_ERROR;
      sema_up (&current_thread->child->load_sema);
      thread_exit ();
      NOT_REACHED ();
    }

  sema_up (&current_thread->child->load_sema);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  struct child_process* child = process_get_child (child_tid);

  if (child == NULL || child->wait)
    return PID_ERROR;

  child->wait = true;

  if (!child->exit)
    sema_down (&child->exit_sema);

  int status = child->status;
  process_remove_child (child);
  return status;
}

/* Creates a new child process. Used by thread.c create_thread() to
   initialise the struct child element of the struct thread. */
struct child_process *
process_add_child (int pid)
{
  struct child_process* child = malloc (sizeof (struct child_process));

  if (child == NULL)
    return NULL;

  child->id = pid;
  child->wait = false;
  child->exit = false;

  sema_init (&child->load_sema, 0);
  sema_init (&child->exit_sema, 0);

  list_push_back (&thread_current ()->process_info->child_list, &child->elem);

  return child;
}

/* Searches for and returns the child process with the id of the integer passed
   in making use of list functions from list.c which return the head, tail and
   next element. */
struct child_process *
process_get_child (int pid)
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

/* Removes the child process and clears the associated memory allocation. */
void
process_remove_child (struct child_process *cp)
{
  list_remove(&cp->elem);
  free(cp);
}

/* Iterates through child_list calling process_remove_child on each element. */
void
process_clear_children (void)
{
  struct thread *t = thread_current();
  struct list_elem *next, *element = list_begin(&t->process_info->child_list);

  while (element != list_end (&t->process_info->child_list))
    {
      next = list_next(element);
      process_remove_child (list_entry(element, struct child_process, elem));
      element = next;
    }
}

struct process_file *
process_get_file_meta (int fd)
{
  struct process_info *info = thread_current ()->process_info;
  struct list_elem *e;

  for (e = list_begin (&info->file_list);
      e != list_end (&info->file_list);
      e = list_next (e))
   {
     struct process_file *file = list_entry (e, struct process_file, elem);

     if (fd == file->fd)
       return file;
   }

  return NULL;
}

/* Searches for and returns the file with the id of the integer passed
   in making use of list functions from list.c which return the head, tail and
   next element. */
struct file *
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

void
process_close_files ()
{
  struct process_info *info = thread_current ()->process_info;

  while (!list_empty (&info->file_list))
    {
      struct list_elem *e = list_pop_front (&info->file_list);
      struct process_file *pf = list_entry (e, struct process_file, elem);
      free (pf->file_name);
      file_close (pf->file);
      list_remove (e);
      free (pf);
    }
}

void
exit (int status)
{
  struct thread * current = thread_current ();
  current->process_info->exit_status = status;

  if (current->process_info->parent_alive && current->child != NULL)
    current->child->status = status;

  thread_exit ();
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Clear child process list. */
  process_clear_children();
  process_close_files ();

  if (cur->holding_filesys_lock)
    {
      lock_release (&filesys_lock);
      cur->holding_filesys_lock = false;
    }

  /* Set exit value to true in case killed by the kernel. */
  if (cur->process_info->parent_alive && cur->child != NULL)
    {
      cur->child->exit = true;
      sema_up(&cur->child->exit_sema);
    }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  if (!cur->is_kernel)
    {
      printf ("%s: exit(%d)\n", cur->name, cur->process_info->exit_status);
      free_process_info (cur);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool has_stack_overflown(void *bottom, void *top, int size);
static bool push_bytes(void **esp, void *val);
static bool setup_stack (uint8_t *kpage, void **esp, char **argv, int argc);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  int length = strlen (file_name) + 1;
  char *file_name_copy = malloc (sizeof (char) * length);

  if (file_name_copy == NULL)
    goto done;

  strlcpy (file_name_copy, file_name, length);
  char *argv[255];
  char *save_ptr;
  argv[0] = strtok_r (file_name_copy, " ", &save_ptr);

  char *token;
  int argc = 1;

  while ((token = strtok_r (NULL, " ", &save_ptr)) != NULL)
    argv[argc++] = token;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name_copy);

  if (file == NULL)
    {
	     printf ("load: %s: open failed\n", file_name_copy);
       goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  uint8_t *kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage == NULL)
    goto done;

  /* Set up stack. */
  if (!setup_stack (kpage, esp, argv, argc))
    {
      palloc_free_page (kpage);
      goto done;
    }

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  free (file_name_copy);
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (uint8_t *kpage, void **esp, char **argv, int argc)
{
  /* Install page. */
  if (!install_page(((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true))
    return false;

  /* Set the stack pointer to physical base and initialize values. */
  *esp = PHYS_BASE;
  int i = argc;
  uint32_t *argv_pointers[argc];

  /* Push each argument to the stack in reverse order. */
  while(--i >= 0)
    {
      int length = strlen (argv[i]) + 1;
      *esp -= length * sizeof (char);
      argv_pointers[i] = (uint32_t *) *esp;
      memcpy(*esp, argv[i], length);
    }

  /* Push a null argument pointer to the stack. */
  if (!push_bytes (esp, 0)) return false;

  /* Push each argument pointer to the stack. */
  i = argc;
  while(--i >= 0)
    if (!push_bytes (esp, argv_pointers[i])) return false;

  /* Push argv, argc and a dummy return address to the stack. */
  void *argv_start = *esp;
  return push_bytes (esp, (void *) argv_start) &&
         push_bytes (esp, (void *) argc) &&
         push_bytes (esp, (void *) NULL);
}

/* Push 4 bytes onto the stack, after first checking we have not
   over run the page. */
static bool
push_bytes(void **esp, void *val)
{
  /* Here we are assuming 32 bit!!! */
  if (has_stack_overflown(*esp, *esp - 4, PGSIZE))
    {
      /* Over page limit so error */
      return false;
    }

  *esp -= 4;
  *((void **)*esp) = val;

  return true;
}

/* Checks whether the stack has overflown. As stacks grow from a
   higher point in memory down, this will expect the bottom of
   the stack to be a higher value than the top.
   BOTTOM Points to the bottom of the stack.
   TOP Points to the top of the stack.
   Returns true if the stack will overflow, otherwise false. */
static bool
has_stack_overflown(void *bottom, void *top, int size)
{
  return (int) bottom - (int) top > size;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* Note we really should only free this once the parent is dead!
   However, as we are not currenlty tracking this in the parent,
   is clearly not actually a problem. */
static void
free_process_info (struct thread *t)
{
  /* This is where we would track all the children processes and
     kill them if necessary */

  /* Free its own metadata if its parent process is dead */
  //  if (!cur->process_info->parent_alive)
  free (t->process_info);
}

//--------------------------------------------------------------------
