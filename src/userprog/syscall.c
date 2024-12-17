#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/user/syscall.h"
#include "process.h"
#include "vm/mmap.h"
#include "vm/frame.h"

/* Error Numbers. */
#define EXIT_ERROR -1
#define FILE_ACCESS_ERROR -1

/* File Descriptors. */
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

/* Argument Passing. */
#define MAX_ARGS 8
#define ONE_ARG 1
#define TWO_ARGS 2
#define THREE_ARGS 3

/* System Calls. */
#define NUM_SYSCALLS 15

typedef void (*syscall_func) (struct intr_frame *, int *args[MAX_ARGS]);

/* System Call Handlers. */
static void syscall_handler (struct intr_frame *);
static void sys_halt_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_exit_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_exec_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_wait_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_create_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_remove_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_open_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_filesize_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_read_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_write_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_seek_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_tell_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_close_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_mmap_handler (struct intr_frame *, int *args[MAX_ARGS]);
static void sys_munmap_handler (struct intr_frame *, int *args[MAX_ARGS]);

/* System Call Implementations. */
static void sys_halt (void);
static pid_t sys_exec (const char *cmd_line);
static int sys_wait (pid_t pid);
static bool sys_create (const char *file, unsigned initial_size);
static bool sys_remove (const char *file);
static int sys_open (const char *file);
static int sys_filesize (int fd);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int fd, const void *buffer, unsigned size);
static void sys_seek (int fd, unsigned position);
static unsigned sys_tell (int fd);
static void sys_close (int fd);
static mapid_t sys_mmap (int fd, void *addr);
static void sys_munmap(mapid_t mapping);

/* Helper Functions. */
static int sys_file_io (int fd, void *buffer, unsigned size, bool is_read);
static void sys_read_write_io(struct intr_frame *f, int *args[MAX_ARGS], bool is_read);
static void validate_buffer (const void *buffer, unsigned size, bool write);
static void validate_ptr (const void *);
static void get_n_arguments (struct intr_frame *f, int *args[MAX_ARGS], int num_args);
static void validate_syscall_nr (int syscall_nr);
static bool valid_fd (int fd, struct thread *cur);
static bool valid_file (struct file *file);
static void validate_fd (int fd, struct thread *cur);
static bool is_overlap (struct thread *cur, void *addr, size_t file_size);
static bool validate_file_name (const char *file);
static bool valid_addr (void *addr);

/* Pinning Helper Functions. */
static void touch_page (void *upage, bool write);
static void pin_page_handler (void *upage, bool pin);
static void touch_buffer (void *buffer, unsigned size, bool write);
static void handle_buffer_pin (void *buffer, unsigned size, bool pin);

/* Local Structures. */
static struct reentrant_lock filesys_lock;
static syscall_func syscall_table[NUM_SYSCALLS];

void
syscall_init (void) 
{
  reentrant_lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  /* Initialise the system call table. */
  syscall_table[SYS_HALT] = sys_halt_handler;
  syscall_table[SYS_EXIT] = sys_exit_handler;
  syscall_table[SYS_EXEC] = sys_exec_handler;
  syscall_table[SYS_WAIT] = sys_wait_handler;
  syscall_table[SYS_CREATE] = sys_create_handler;
  syscall_table[SYS_REMOVE] = sys_remove_handler;
  syscall_table[SYS_OPEN] = sys_open_handler;
  syscall_table[SYS_FILESIZE] = sys_filesize_handler;
  syscall_table[SYS_READ] = sys_read_handler;
  syscall_table[SYS_WRITE] = sys_write_handler;
  syscall_table[SYS_SEEK] = sys_seek_handler;
  syscall_table[SYS_TELL] = sys_tell_handler;
  syscall_table[SYS_CLOSE] = sys_close_handler;
#ifdef VM
  syscall_table[SYS_MMAP] = sys_mmap_handler;
  syscall_table[SYS_MUNMAP] = sys_munmap_handler;
#else
  syscall_table[SYS_MMAP] = NULL;
  syscall_table[SYS_MUNMAP] = NULL;
#endif
}

static void
sys_halt_handler (struct intr_frame *f UNUSED, int *args[MAX_ARGS] UNUSED)
{
  sys_halt ();
}

static void
sys_exit_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  int status = (int) args[0];
  sys_exit (status);
}

static void
sys_exec_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  const char *cmd_line = (const char *) args[0];
  f->eax = sys_exec (cmd_line);
}

static void
sys_wait_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  pid_t pid = (pid_t) args[0];
  f->eax = sys_wait (pid);
}

static void
sys_create_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, TWO_ARGS);
  const char *file = (const char *) args[0];
  unsigned initial_size = (unsigned) args[1];
  f->eax = sys_create (file, initial_size);
}

static void
sys_remove_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  const char *file = (const char *) args[0];
  f->eax = sys_remove (file);
}

static void
sys_open_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  const char *file = (const char *) args[0];
  f->eax = sys_open (file);
}

static void
sys_filesize_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  int fd = (int) args[0];
  f->eax = sys_filesize (fd);
}

static void
sys_read_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  sys_read_write_io(f, args, true);
}

static void
sys_seek_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, TWO_ARGS);
  int fd = (int) args[0];
  unsigned position = (unsigned) args[1];
  sys_seek (fd, position);
}

static void
sys_tell_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  int fd = (int) args[0];
  f->eax = sys_tell (fd);
}

static void
sys_write_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  sys_read_write_io(f, args, false);
}

static void
sys_close_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  int fd = (int) args[0];
  sys_close (fd);
}

#ifdef VM
static void
sys_mmap_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, TWO_ARGS);
  int fd = (int) args[0];
  void *addr = (void *) args[1];
  f->eax = sys_mmap (fd, addr);
}

static void
sys_munmap_handler (struct intr_frame *f, int *args[MAX_ARGS])
{
  get_n_arguments (f, args, ONE_ARG);
  mapid_t mapping = (mapid_t) args[0];
  sys_munmap (mapping);
}
#endif

static void
syscall_handler (struct intr_frame *f)
{
  int *esp = f->esp;
  validate_ptr (esp);
  int syscall_nr = *esp;
  validate_syscall_nr (syscall_nr);
  int *args[MAX_ARGS];
  /* Dispatch to appropriate call handler. */
  syscall_table[syscall_nr] (f, args);
}

static void
sys_halt (void)
{
  shutdown_power_off ();
}

/* Terminates current user program, returning status to kernel. */
void
sys_exit (int status)
{
  enum intr_level old_level = intr_disable ();

  struct thread *cur = thread_current ();

  cur->exit_code = status;

  intr_set_level (old_level);
  thread_exit ();
}

/* Runs the executable and returns the new process' pid. */
static pid_t
sys_exec (const char *cmd_line)
{
  validate_ptr ((const void *) cmd_line);
  pid_t pid = process_execute (cmd_line);
  return pid;
}

/* Waits for a child process to terminate. */
static int
sys_wait (pid_t pid)
{
  return process_wait (pid);
}

/* Creates a new file and returns true if successful, false otherwise. */
static bool
sys_create (const char *file, unsigned initial_size)
{
  if (!validate_file_name (file))
    return false;
  acquire_filesys_lock ();
  bool success = filesys_create (file, initial_size);
  release_filesys_lock ();
  return success;
}

/* Removes a file and returns true if successful, false otherwise. */
static bool
sys_remove (const char *file)
{
  if (!validate_file_name (file))
    return false;
  acquire_filesys_lock ();
  bool success = filesys_remove (file);
  release_filesys_lock ();
  return success;
}

/* Opens a file and returns the file descriptor. */
static int
sys_open (const char *file)
{
  if (!validate_file_name (file))
    return FILE_ACCESS_ERROR;

  acquire_filesys_lock ();
  struct file *f = filesys_open (file);
  release_filesys_lock ();

  if (f == NULL)
    return FILE_ACCESS_ERROR;

  struct thread *cur = thread_current ();
  int fd;

  /* Reuse fd from free list if available. */
  if (!list_empty (&cur->free_fds))
    {
      struct list_elem *e = list_pop_front (&cur->free_fds);
      struct fd_elem *fde = list_entry (e, struct fd_elem, elem);
      fd = fde->fd;
      free (fde);
    }
  else
    {
      fd = cur->next_fd;

      /* Resize the fd_table if necessary. */
      if (fd >= cur->fd_table_size)
        {
          /* Double the size of the fd_table. */
          int new_size = cur->fd_table_size * 2;
          struct file **new_fd_table = realloc (cur->fd_table, 
                                                sizeof (struct file *) * new_size);
          if (new_fd_table == NULL)
            {
              /* Handle allocation failure. */
              acquire_filesys_lock ();
              file_close (f);
              release_filesys_lock ();
              return FILE_ACCESS_ERROR;
            }

          /* Initialize new entries to NULL. */
          for (int i = cur->fd_table_size; i < new_size; i++)
            new_fd_table[i] = NULL;

          cur->fd_table = new_fd_table;
          cur->fd_table_size = new_size;
        }

      cur->next_fd++;
    }

  /* Assign the file to the fd_table. */
  cur->fd_table[fd] = f;

  return fd;
}

static int
sys_filesize (int fd)
{
  struct thread *cur = thread_current ();
  validate_fd (fd, cur);
  acquire_filesys_lock ();
  int size = file_length (cur->fd_table[fd]);
  release_filesys_lock ();

  return size;
}

/* Manages file IO system calls. */
static int
sys_file_io (int fd, void *buffer, unsigned size, bool is_read)
{
  struct thread *cur = thread_current ();
  validate_fd (fd, cur);
  handle_buffer_pin (buffer, size, true);

  acquire_filesys_lock ();
  int result;
  if (is_read) {
    result = file_read (cur->fd_table[fd], buffer, size);
  }
  else {
    result = file_write (cur->fd_table[fd], buffer, size);
  }
  release_filesys_lock ();
  handle_buffer_pin (buffer, size, false);
  return result;
}

/* Reads from the file descriptor. */
static int
sys_read (int fd, void *buffer, unsigned size)
{
  validate_buffer (buffer, size, true);

  if (fd == STDIN_FILENO)
    {
      int bytes_read = 0;
      unsigned i;

      for (i = 0; i < size; i++)
        {
          ((uint8_t *) buffer)[i] = input_getc ();
          bytes_read++;
        }

      return bytes_read;
    }
  else
    {
      return sys_file_io (fd, buffer, size, true);
    }
}

static void
sys_seek (int fd, unsigned position)
{
  struct thread *cur = thread_current ();
  validate_fd (fd, cur);

  acquire_filesys_lock ();
  file_seek (cur->fd_table[fd], position);
  release_filesys_lock ();
}

static unsigned
sys_tell (int fd)
{
  struct thread *cur = thread_current ();
  validate_fd (fd, cur);

  acquire_filesys_lock ();
  unsigned position = file_tell (cur->fd_table[fd]);
  release_filesys_lock ();

  return position;
}

/* Writes to the file descriptor. */
static int
sys_write (int fd, const void *buffer, unsigned size)
{
  validate_buffer (buffer, size, false);
  unsigned buffer_chunk_size = 300;
  if (fd == STDOUT_FILENO)
    {
      if (size < buffer_chunk_size)
        putbuf (buffer, size);
      
      return size;
    }
  else
    {
      return sys_file_io (fd, (void *) buffer, size, false);
    }
}

/* Manages read/write system calls */
static void
sys_read_write_io(struct intr_frame *f, int *args[MAX_ARGS], bool is_read)
{
  acquire_filesys_lock ();
  get_n_arguments(f, args, THREE_ARGS);
  int fd = (int) args[0];
  void *read_buffer = (void *) args[1];
  const void *write_buffer = (void *) args[1];
  unsigned size = (unsigned) args[2];
  if(is_read)
  {
    f->eax = sys_read(fd, read_buffer, size);
  }
  else {
    f->eax = sys_write(fd, write_buffer, size);
  }
  release_filesys_lock ();
}

/* Close file descriptor fd. */
static void
sys_close (int fd)
{
  struct thread *cur = thread_current ();
  validate_fd (fd, cur);
  acquire_filesys_lock ();
  file_close (cur->fd_table[fd]);
  release_filesys_lock ();

  cur->fd_table[fd] = NULL;
  /* Add fd to the free list */
  struct fd_elem *fde = malloc (sizeof (struct fd_elem));
  if (fde == NULL)
      sys_exit (FILE_ACCESS_ERROR);

  fde->fd = fd;
  list_push_front(&cur->free_fds, &fde->elem);
}

#ifdef VM
/* Maps the file open as fd into the process’s virtual address space.
   The entire file is mapped into consecutive virtual pages starting at addr. */
static mapid_t
sys_mmap (int fd, void *addr)
{
  struct thread *cur = thread_current ();
  if (!valid_fd (fd, cur) || !valid_addr (addr))
    return MAP_FAILED;

  acquire_filesys_lock ();
  struct file *f = file_reopen (cur->fd_table[fd]);
  if (!valid_file (f))
    goto mapping_failed;

  size_t file_size = file_length (f);
  if (is_overlap (cur, addr, file_size))
    goto mapping_failed;

  release_filesys_lock ();
  return mm_insert (addr, f, file_size)->mapping;

mapping_failed:
  release_filesys_lock ();
  return MAP_FAILED;
}

/* Unmaps the mapping designated by mapping, which must be a mapping id
   returned by a previous call to mmap by the same process that has not
   yet been unmapped. */
static void
sys_munmap (mapid_t mapping)
{
  acquire_frame_table_lock ();
  struct thread *cur = thread_current ();
  struct mm_entry *mme = mm_entry_find (mapping);
  if (mme == NULL)
    sys_exit (EXIT_ERROR); /* Handles invalid mapping. */

  mm_destroy_entry (cur, mme);
  release_frame_table_lock ();
}
#endif

/* Validates a user-provided pointer. */
static void
validate_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr))
    sys_exit (EXIT_ERROR);

  /* Check if the pointer points to unmapped virtual memory. */
  reentrant_lock_acquire (&thread_current ()->spt.lock);
  struct spt_entry *spte = spt_entry_find (&thread_current ()->spt, (void*) ptr);
  reentrant_lock_release (&thread_current ()->spt.lock);

  if (spte == NULL)
    sys_exit (EXIT_ERROR);

  touch_page ((void *) ptr, false);

}

/* Validates a buffer passed in from user space. */
static void
validate_buffer (const void *buffer, unsigned size, bool write)
{
  void *current_ptr;
  touch_buffer ((void *) buffer, size, write);
  for (
    current_ptr = (void *) buffer;
    pg_round_down (current_ptr) <= buffer + size;
    current_ptr += PGSIZE
  )
    {
      validate_ptr (current_ptr);
    }
}

static void
get_n_arguments (struct intr_frame *f, int *args[MAX_ARGS], int num_args)
{
  int i;
  int *ptr;

  for (i = 0; i < num_args; i++)
    {
      ptr = (int *) f->esp + i + 1;
      validate_ptr ((const void *) ptr);
      args[i] = (int *) *ptr;
    }
}

static void
validate_syscall_nr (int syscall_nr)
{
  if (syscall_nr < 0 || syscall_nr >= NUM_SYSCALLS || syscall_table[syscall_nr] == NULL)
    sys_exit (EXIT_ERROR);
}

static void
validate_fd (int fd, struct thread *cur)
{
  if (!valid_fd (fd, cur))
    sys_exit (EXIT_ERROR);
}

static bool
valid_fd (int fd, struct thread *cur)
{
  return (fd >= FDT_START && fd < cur->fd_table_size && cur->fd_table[fd] != NULL);
}

static bool
valid_file (struct file *f)
{
  if (f == NULL)
    return false;
  size_t file_size = file_length (f);
  if (file_size == 0)
    return false;
  return true;
}

static bool
is_overlap (struct thread *cur, void *addr, size_t file_size)
{
  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE)
    {
      void *upage = addr + offset;
      if (spt_entry_find (&cur->spt, upage) != NULL)
        return true;
    }
  return false;
}

static bool
valid_addr (void *addr)
{
  return (addr != NULL && addr != 0 && pg_ofs (addr) == 0);
}

static bool
validate_file_name (const char *file)
{
  validate_ptr ((const void *) file);
  return (strlen(file) <= MAX_FILE_NAME_LENGTH);
}

/* Touch a page - mock read and write to said page
  to trigger a page fault if not present. */
static void
touch_page (void *upage, bool write)
{
  acquire_frame_table_lock ();
  char x = (char) *((char *) upage);
  barrier ();
  if (write)
    {
      *((char *) upage) = 'a';
      barrier ();
      *((char *) upage) = x;
    }
  release_frame_table_lock ();
}

/* Ensure buffer can be read / written to so a page 
  fault is not caused inside of file operations. */
static void
touch_buffer (void *buffer, unsigned size, bool write)
{
  acquire_frame_table_lock ();
  void *start_page = pg_round_down (buffer);
  void *end_page = pg_round_down (buffer + size);
  for (void *page_addr = start_page; page_addr <= end_page; page_addr += PGSIZE)
    {
      touch_page (page_addr, write);
    }
  release_frame_table_lock ();
}

static void
pin_page_handler (void *upage, bool pin)
{
  acquire_frame_table_lock ();
  /* Get physical page */
  void *kpage = pagedir_get_page (thread_current ()->pagedir, upage);
  if (kpage != NULL)
   {
    struct frame_table_entry *fte = ft_entry_find ((void *) vtop (kpage));
    if (fte != NULL)
      {
       fte->pinned = pin;
      }
   }
  release_frame_table_lock ();
}

static void
handle_buffer_pin (void *buffer, unsigned size, bool pin)
{
  acquire_frame_table_lock ();
  void *start_page = pg_round_down (buffer);
  void *end_page = pg_round_down (buffer + size);

  for (void *page_addr = start_page; page_addr <= end_page; page_addr += PGSIZE)
    {
      pin_page_handler (page_addr, pin);
    }
  release_frame_table_lock ();
}

void acquire_filesys_lock (void)
{
  reentrant_lock_acquire (&filesys_lock);
}

void release_filesys_lock (void)
{
  reentrant_lock_release (&filesys_lock);
}

void relinquish_filesys_lock (void)
{
  reentrant_lock_relinquish (&filesys_lock);
}