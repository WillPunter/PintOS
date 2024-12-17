#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include "vm/frame.h"
#include "vm/fpt.h"
#include "syscall.h"

#define WORD_SIZE 4
#define NULL_POINTER_SENTINEL &(void *){0}
#define FAKE_RETURN_ADDRESS &(void *){0}

/* Initial size of the dynamic array storing file descriptors. */
#define INITIAL_FD_TABLE_SIZE 4

#define PUSH_TO_STACK(ESP, ARG, SIZE) \
  (ESP) -= (SIZE); \
  memcpy ((ESP), (ARG), (SIZE));

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Stores the arguments of a process
   and their metadata. */
struct file_page_args {
  char *file_name_page; /* Address of page storing all the arguments as contiguous null-terminated strings. */
  char **args;          /* Array of ptrs to arguments in above buffer. Null terminated. */
  int num_args;         /* Number of arguments. */ 
};

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name)
{
  enum intr_level old_level = intr_disable ();

  /* Initialise all dynamically allocated structures to null. */
  char **args_array = NULL;
  struct file_page_args *fpa = NULL;
  struct child_thread *child_buf = NULL;

  char *fn_copy;
  tid_t tid;
  size_t current_total_size = 0;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* Calculate total size needed for arguments on
     user process stack. We start by adding the
     minimum amount of data, i.e. the data stored
     on an execute call with no arguments. */
  current_total_size += sizeof (void *);                /* Fake return address. */
  current_total_size += sizeof (int);                   /* argc. */
  current_total_size += sizeof (char **);               /* argv. */
  current_total_size += sizeof (uint8_t) * WORD_SIZE;   /* Maximum Padding to nearest multiple of 4 bytes. */
  current_total_size += sizeof (char *);                /* Null sentinel. */

  /* Count the number of arguments (tokens).
     Each space-separated word is a token. */

  size_t fn_len = strlen (fn_copy);
  size_t tokens = 0;
  bool new_token = true;
  size_t i;

  for (i = 0; i < fn_len; i++)
    {
      if (fn_copy[i] == ' ')
        {
          new_token = true;
        }
      else
        {
          if (new_token)
            {
              tokens++;
              new_token = false;
            }
        }
    }

  /* Allocate the argument array. */
  args_array = malloc ((tokens + 1) * sizeof (char *));
  if (args_array == NULL)
    {
      goto exit;
    }

  /* Add the strings to the array of arguments. */
  char *save_ptr;
  for (
    i = 0;
    (args_array[i] = strtok_r (i == 0 ? fn_copy : NULL, " ", &save_ptr)) != NULL;
    i++)
    {
      /* i < tokens should always be true as 
      strtok_r should find the same number of 
      tokens as we previously counted. */
      ASSERT (i < tokens);

      /* Stack must store the null-terminated arg string as 
      well as a pointer to it as an element of argvs. */
      current_total_size += strlen (args_array[i]) + 1;
      current_total_size += sizeof (char *);

      if (current_total_size >= PGSIZE)
        {
          goto exit;
        }
    }

  if (strlen (args_array[0]) > MAX_FILE_NAME_LENGTH)
    {
      goto exit;
    }

  /* Allocate file page arguments structure and
     give it pointers to the file name page and
     array of arg pointers. Also provide the
     number of arguments for use by the newly
     created process. */
  fpa = malloc (sizeof (struct file_page_args));

  if (fpa == NULL)
    {
      goto exit;
    }

  *fpa = (struct file_page_args) {.file_name_page = fn_copy, 
                                  .args = args_array,
                                  .num_args = tokens};
  
  /* Allocate child buf for use in parent thread for
     storing exit information about soon-to-be created
     child. */
  child_buf = malloc (sizeof (struct child_thread));
  if (child_buf == NULL)
    {
      goto exit;
    }

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args_array[0], PRI_DEFAULT, start_process, fpa);

  if (tid == TID_ERROR)
    {
      goto exit;
    }
  else
    {
      /* Add new thread to child threads. */
      struct thread *t = thread_current ();
      struct thread *child = get_thread_from_tid (tid);
      child->is_user_proc = true;
      init_child_thread (child_buf, tid);
      list_push_back (&t->children, &child_buf->elem);

      child->child_data = child_buf;

      /* Wait for child process to load file. */
      sema_down (&child_buf->wait_sema);

      /* Handle error cases where process has not loaded. Note
         that this should not be treated as an error in the
         parent process, but should simply return TID_ERROR.
         The child arguments and FPA structure are deallocated
         in start_process' load call so do not need to be
         deallocated here. */
      if (!child_buf->load_success)
        {
          tid = TID_ERROR;
        }
    }

  intr_set_level (old_level);
  return tid;
  NOT_REACHED ();

  /* This is only reached if an error has occurred
     such that process_execute cannot correctly
     terminate. Free all allocated resources, re-enable
     interrupts and return with an error. */
exit:
  if (args_array)
    {
      free (args_array);
    }
    
  if (fpa)
    {
      free (fpa);
    }
    
  if (child_buf)
    {
      free (child_buf);
    }

  palloc_free_page (fn_copy);
  intr_set_level (old_level);
  return TID_ERROR;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  struct file_page_args *fpa = file_name_;
  char **args_array = fpa->args;
  struct intr_frame if_;
  bool success;
  char *arg_addresses[fpa->num_args];

  struct thread *t = thread_current ();

  /* Initialize the file descriptor table. */
  t->fd_table_size = INITIAL_FD_TABLE_SIZE;
  t->fd_table = malloc (sizeof (struct file *) * INITIAL_FD_TABLE_SIZE);
  
  /* Initialize all entries to NULL. */
  for (int i = 0; i < t->fd_table_size; i++)
      t->fd_table[i] = NULL;

  /* Initialise supplemental page table. */
  spt_init (&t->spt);

  /* Initialise the memory map table. */
  mm_init (&t->mm_table);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (args_array[0], &if_.eip, &if_.esp);

  enum intr_level old_level = intr_disable ();

  if (success)
    {
      /* Push arguments to the stack, and save the 
      addresses to push to the stack later. */
      for (int i = 0; i < fpa->num_args; i++)
        { 
          ASSERT (args_array[i] != NULL);

          size_t arg_len = strlen (args_array[i]) + 1;
          PUSH_TO_STACK (if_.esp, args_array[i], arg_len);
          arg_addresses[i] = if_.esp;
        }

        /* Pad to the nearest multiple of 4 bytes. */
        if_.esp -= (uint32_t) if_.esp % WORD_SIZE;

        /* Push null pointer sentinel to stack. */
        PUSH_TO_STACK (if_.esp, NULL_POINTER_SENTINEL, sizeof (void *));

        /* Push argument pointers to stack. */
        PUSH_TO_STACK (if_.esp, arg_addresses, sizeof (char *) * fpa->num_args);
        char *argv_address = if_.esp;
        
        /* Push argv and argc to stack. */
        PUSH_TO_STACK (if_.esp, &argv_address, sizeof (void *));
        PUSH_TO_STACK (if_.esp, &fpa->num_args, sizeof (int));

        /* Push fake return address to stack. */
        PUSH_TO_STACK (if_.esp, FAKE_RETURN_ADDRESS, sizeof (void *));
    }

  palloc_free_page (fpa->file_name_page);
  free (fpa->args);
  free (fpa);

  if (t->child_data != NULL && !t->parent_terminated)
    {
      /* Process has successfully created - up the semaphore of the parent. */
      t->child_data->load_success = success;
      sema_up (&t->child_data->wait_sema);
    }

  if (!success)
    {
      thread_exit ();
    }

  intr_set_level (old_level);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{
  enum intr_level old_level = intr_disable ();
  struct thread *t = thread_current ();
  int result = -1;

  /* Check the current thread's children for the given child thread. */
  for (struct list_elem *e = list_begin (&t->children);
       e != list_end (&t->children);
       e = list_next (e))
    {
      struct child_thread *ct = list_entry (e, struct child_thread, elem);
      
      if (ct->child_tid == child_tid)
        {
          /* Block if child has not exited yet. */
          sema_down (&ct->wait_sema);
          if (ct->has_exited)
            {
              result = ct->exit_code;
            }
          
          list_remove (e);
          free (ct);
          break;
        }
    } 

  intr_set_level (old_level);
  return result;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  mm_destroy ();
  enum intr_level old_level = intr_disable ();

  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy supplemental page table, deleting
     all elements in it and their corresponding
     values in the frame table. */
  spt_destroy (&thread_current ()->spt);

  /* We close the source file when the process exits to 
  ensure no other file can overwrite it. */
  if (cur->source_file != NULL)
    {
      acquire_filesys_lock ();
      file_close (cur->source_file);
      release_filesys_lock ();
    }

  /* Kernel threads should not print an exit message. */
  if (cur->is_user_proc)
    {
      printf ("%s: exit(%d)\n", cur->name, cur->exit_code);
    }

  for (int i = FDT_START; i < cur->fd_table_size; i++)
    {
      if (cur->fd_table[i] != NULL)
        {
          acquire_filesys_lock ();
          file_close (cur->fd_table[i]);
          release_filesys_lock ();
        }
    }

  free(cur->fd_table);

  /* Free any remaining fd_elem structures. */
  while (!list_empty(&cur->free_fds))
  {
      struct list_elem *e = list_pop_front(&cur->free_fds);
      struct fd_elem *fde = list_entry(e, struct fd_elem, elem);
      free(fde);
  }

  /* Wake up a parent thread waiting for this 
  thread if the parent has not yet terminated. */
  if (!cur->parent_terminated && cur->child_data != NULL)
    {
      if (!cur->child_data->has_exited)
        {
          /* The process should exit with a positive number only when
             exiting via a syscall. Exit with -1 otherwise. */
          cur->child_data->exit_code = cur->exit_code;
          cur->child_data->has_exited = true;
          sema_up (&cur->child_data->wait_sema);
        }
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

  /* Clean up remaining child threads. */
  struct list_elem *child = list_begin (&cur->children);
  struct list_elem *next;
  struct child_thread *ct;

  while (child != list_end (&cur->children))
    {
      next = child->next;
      list_remove (child);
      ct = list_entry (child, struct child_thread, elem);

      struct thread *child_from_list = get_thread_from_tid (ct->child_tid);

      if (child_from_list != NULL)
        {
          child_from_list->parent_terminated = true;
          child_from_list->child_data = NULL;
        }

      free (ct);
      child = next;
    }

  /* Relinquish global locks if held. */
  relinquish_filesys_lock ();
  relinquish_frame_table_lock ();
  relinquish_file_page_table_lock();

  intr_set_level (old_level);
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

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage,
                         uint32_t read_bytes, uint32_t zero_bytes,
                         bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  acquire_filesys_lock ();

  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
  file_deny_write (file);

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

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  t->source_file = file; 

 done:
  /* We arrive here whether the load is successful or not. */
  release_filesys_lock ();
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  acquire_filesys_lock ();
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    {
      release_filesys_lock ();
      return false;
    }
  release_filesys_lock ();

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

  acquire_filesys_lock ();
  file_seek (file, ofs);
  release_filesys_lock ();

  while (read_bytes > 0 || zero_bytes > 0) 
  {
    /* Calculate how to fill this page.
     We will read PAGE_READ_BYTES bytes from FILE
     and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

#ifdef VM
    /* Lazy loading. */
    struct thread *t = thread_current ();     
    if (pagedir_get_page (t->pagedir, upage) != NULL)
    {
      return false;
    }

    lazy_load_spt_file(file, ofs, page_read_bytes, page_zero_bytes, t, upage, writable);
#else
    /* Check if virtual page already allocated. */
    struct thread *t = thread_current ();
    uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
    
    if (kpage == NULL)
    {
      /* Get a new page of memory. */
      kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;
      
      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
      {
        palloc_free_page (kpage);
        return false; 
      }     
    } 
    else 
    {
      /* Check if writable flag for the page should be updated */
      if (writable && !pagedir_is_writable (t->pagedir, upage))
        pagedir_set_writable (t->pagedir, upage, writable); 
    }

    /* Load data into the page. */
    acquire_filesys_lock ();
    if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
    {
      release_filesys_lock ();
      return false; 
    }
    release_filesys_lock ();
    memset (kpage + page_read_bytes, 0, page_zero_bytes);
#endif
    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
#ifdef VM
    ofs += PGSIZE;
#endif
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  /* Use the arguments passed to set up stack */
  bool success = false;

  void *user_address = ((uint8_t *) PHYS_BASE) - PGSIZE;

  if (allocate_user_page (user_address, true) != NULL)
    {
      *esp = PHYS_BASE;
      success = true;
    };

  return success;
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
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
