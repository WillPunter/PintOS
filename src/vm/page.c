#include "vm/page.h"
#include <debug.h>
#include <stdio.h>
#include "threads/vaddr.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "filesys/file.h"
#include "devices/swap.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "vm/fpt.h"
#include "threads/interrupt.h"
#include "userprog/pagedir.h"

static void spt_init_frame (struct spt_entry *spte, void *upage, void *aux UNUSED);
static void spt_init_file (struct spt_entry *spte, void *upage, void *file_data);
static void spt_init_swap (struct spt_entry *spte, void *upage, void *swap_slot);
static void spt_init_zero (struct spt_entry *spte, void *upage, void *aux UNUSED);
static bool spt_insert (struct s_pg_table *spt, void (*entry_init) (struct spt_entry *, void *, void *), void *aux1, void *aux2, bool writable);

/* Initializes the supplemental page table - creates a corresponding
  hash table and lock. */
void
spt_init (struct s_pg_table *pt)
{
  hash_init (&pt->table, spt_hash, spt_less, NULL);
  reentrant_lock_init (&pt->lock);
}

/* Hash function for supplemental page table. */
unsigned
spt_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  return hash_bytes (&spte->upage, sizeof spte->upage);
}

/* Comparison function for supplemental page table. */
bool
spt_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct spt_entry *spte_a = hash_entry (a, struct spt_entry, elem);
  const struct spt_entry *spte_b = hash_entry (b, struct spt_entry, elem);
  return spte_a->upage < spte_b->upage;
}

/* Finds and returns the supplemental page table entry for the given virtual address. */
struct spt_entry *
spt_entry_find (struct s_pg_table *spt, void *upage)
{
  reentrant_lock_acquire (&spt->lock);

  struct spt_entry spte_temp;
  struct hash_elem *e;

  /* Initialize a temporary spt_entry with the page-aligned address. */
  spte_temp.upage = pg_round_down (upage);
  e = hash_find (&spt->table, &spte_temp.elem);

  struct spt_entry *result;

  if (e == NULL)
   result = NULL;
  else
   result = hash_entry (e, struct spt_entry, elem);

  reentrant_lock_release (&spt->lock);

  return result;
}

/* Free a given element from a supplemental page table. */
static void
spt_destroy_elem (struct hash_elem *e, void *aux UNUSED)
{
  struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);

  /* Remove entry from frame table if it is a frame. */
  if (spte->type == PAGE_FRAME)
   {
    /* Get physical address - lookup page in page table. */
    void *kpage = pagedir_get_page (thread_current ()->pagedir, spte->upage);

    if (kpage != NULL)
      {
        /* Remove corresponding element from frame table if not shared. */
        void *paddr = (void *) vtop (kpage);
        bool no_more_owners = ft_remove (paddr, thread_current ());

        /* Remove from the page directory. */
        pagedir_clear_page (thread_current ()->pagedir, spte->upage);

        /* Remove corresponding element from file page table if there are no owners left
           for the page. */
        if (no_more_owners)
          {
            palloc_free_page (kpage);

            if (spte->file_data.file != NULL)
              {
                /* Remove from file page table. */
                fpt_remove_page (spte->file_data.file, spte->file_data.offset, spte->upage);
              }
          }
      }
   }
  /* Remove entry from the swap disk if it is present there. */
  else if (spte->type == PAGE_SWAP)
  {
    swap_drop (spte->swap_slot);
  }

  free (spte);
}

/* Free a supplemental page table including all of its elements. */
void
spt_destroy (struct s_pg_table *spt)
{
  acquire_frame_table_lock ();
  reentrant_lock_acquire (&spt->lock);
  hash_destroy (&spt->table, spt_destroy_elem);
  reentrant_lock_release (&spt->lock);
  release_frame_table_lock ();
}

/* Entry initializer functions. These initialize
  an entry with the given values. */
static void
spt_init_frame (struct spt_entry *spte, void *upage, void *aux UNUSED)
{
  spte->type = PAGE_FRAME;
  spte->upage = upage;
}

static void
spt_init_file (struct spt_entry *spte, void *upage, void *file_data)
{
  spte->type = PAGE_FILE;
  spte->upage = upage;

  memcpy (&spte->file_data, file_data, sizeof (struct file_data));
}

static void
spt_init_swap (struct spt_entry *spte, void *upage, void *swap_slot)
{
  spte->type = PAGE_SWAP;
  spte->upage = upage;
  spte->swap_slot = (size_t) swap_slot;
}

static void
spt_init_zero (struct spt_entry *spte, void *upage, void *aux UNUSED)
{
  spte->type = PAGE_ZERO;
  spte->upage = upage;
}

/* Allocates a new spte entry, initializes it with
  the provided function and auxiliary data and then
  inserts it into the table - removing and freeing
  an existing entry with the same user page address. */
static bool
spt_insert (struct s_pg_table *spt, void (*entry_init) (struct spt_entry *, void *, void *), void *aux1, void *aux2, bool writable)
{
  reentrant_lock_acquire (&spt->lock);
  struct spt_entry *spte = malloc (sizeof (struct spt_entry));

  if (spte == NULL)
    {
      reentrant_lock_release (&spt->lock);
      return false;
    }

  spte->file_data.file = NULL;
  spte->writable = writable;
  entry_init (spte, aux1, aux2);
  spte->writable = writable;

  struct hash_elem *old = hash_replace (&spt->table, &spte->elem);

  /* We need to free the removed element returned by hash_replace. */
  if (old != NULL)
   {
    free (hash_entry (old, struct spt_entry, elem));
   }

  reentrant_lock_release (&spt->lock);
  return true;
}

/* Insert a frame mapping - upage maps to a frame in physical
  memory. */
bool
spt_insert_frame (struct s_pg_table *spt, void *upage, bool writable)
{
  return spt_insert (spt, spt_init_frame, upage, NULL, writable);
}

/* Insert a file mapping - upage maps to a page stored in
  a file on disk. */
bool
spt_insert_file (struct s_pg_table *spt, void *upage, struct file_data *file_data, bool writable)
{
  return spt_insert (spt, spt_init_file, upage, (void *) file_data, writable);
}

/* Insert a swap mapping - upage maps to a frame in the
  swap buffer on disk. */
bool
spt_insert_swap (struct s_pg_table *spt, void *upage, size_t swap_slot, bool writable)
{
  return spt_insert (spt, spt_init_swap, upage, (void *) swap_slot, writable);
}

/* Insert a zero mapping - upage maps to a zero page. This
  doesn't have to be stored in RAM because all of its data
  is zero. */
bool
spt_insert_zero (struct s_pg_table *spt, void *upage, bool writable)
{
  return spt_insert (spt, spt_init_zero, upage, NULL, writable);
}

static bool load_shared_page (struct spt_entry *spte)
{
  struct thread *cur = thread_current ();
  struct reentrant_lock *spt_lock = &cur->spt.lock;
  acquire_frame_table_lock ();
  reentrant_lock_acquire (spt_lock);

  /* If searching for a file page, check the file
    page table to see if it is already in memory and
    can be shared. */
  if (spte->type == PAGE_FILE)
    {
      struct fpt_page_entry *pe
        = fpt_page_lookup (spte->file_data.file, spte->file_data.offset, spte->upage);
      
      if (pe == NULL)
        goto cannot_share_page;

      /* Get frame table entry for given physical address. */
      struct frame_table_entry *fte = ft_entry_find (pe->paddr);

      if (fte == NULL)
        goto cannot_share_page;

      /* Iterate through sharing threads in frame table entry to
        check if the frame was dirty or writable. */
      bool page_is_dirty = false;
      bool page_is_writable = false;

      struct list *owner_list = &fte->owner_list;
      struct list_elem *e = list_begin (owner_list);
      void *paddr = ptov ((uintptr_t) pe->paddr);

      while (e != list_end (owner_list))
        {
          struct frame_owner *f = list_entry (e, struct frame_owner, elem);

          /* We only share read-only pages read in from executable files.
              If a page is dirty, then it has been modified at some point
              since loading, and if it is writable then it is not read-only
              so should not be shared. We check both the page itself and
              its kernel alias. */

          uint32_t *pagedir = f->owner->pagedir;
          void *vaddr = f->vaddr;

          if (pagedir_is_dirty (pagedir, vaddr) || pagedir_is_dirty (pagedir, paddr))
            page_is_dirty = true;
          
          if (pagedir_is_writable (pagedir, vaddr) || pagedir_is_writable (pagedir, paddr))
            page_is_writable = true;
          
          e = list_next (e);
        }
      
      if (page_is_dirty || page_is_writable)
        goto cannot_share_page;

      /* Add current thread to frame table list of owners. */
      struct frame_owner *fo = malloc (sizeof (struct frame_owner));

      if (fo == NULL)
        goto cannot_share_page;

      fo->owner = cur;
      fo->vaddr = spte->upage;
      list_push_back (&fte->owner_list, &fo->elem);

      /* File page is already loaded modify the page directory
        to point to this physical address. */
      install_page (spte->upage, paddr, spte->writable);
      spte->type = PAGE_FRAME;
      
      reentrant_lock_release (spt_lock);
      release_frame_table_lock ();
      return true;
    }

cannot_share_page:
  reentrant_lock_release (spt_lock);
  release_frame_table_lock ();
  return false;
}

/* Used in page_fault in exception.c to load data into the page table. */
bool
load_page (struct spt_entry *spte)
{
  struct thread *cur = thread_current ();
  struct reentrant_lock *spt_lock = &cur->spt.lock;
  acquire_frame_table_lock ();
  reentrant_lock_acquire (spt_lock);

  if (load_shared_page (spte))
    {
      reentrant_lock_release (spt_lock);
      release_frame_table_lock ();
      return true;
    }

  /* 2. Obtain a frame to store the page. */
  void *kpage = obtain_frame (spte->upage);
  ASSERT (kpage != NULL);

  /* 3. Fetch the data into the frame, by reading it from the file system or swap, zeroing it, etc. */
  bool success = false;
  bool swap = false;
  switch (spte->type)
   {
   case PAGE_FILE:
    success = load_page_from_file (spte, kpage);
    break;
   case PAGE_SWAP:
    swap = true;
    success = load_page_from_swap (spte, kpage);
    break;
   case PAGE_ZERO:
    success = allocate_zero_page (kpage);
    break;
   case PAGE_FRAME:
    success = true; /* Frame is already loaded. */
    break;
   default:
    success = false;
    break;
   }

  /* 4. Point the page table entry for the faulting virtual address to the frame. */
  if (!success || !install_page (spte->upage, kpage, spte->writable))
   {
    palloc_free_page (kpage);
    reentrant_lock_release (spt_lock);
    release_frame_table_lock ();
    return false;
   }
  
  spte->type = PAGE_FRAME;

  if (swap)
    {
      pagedir_set_dirty (cur->pagedir, spte->upage, true);
    }

  reentrant_lock_release (spt_lock);
  release_frame_table_lock ();
  return true;
}

bool
load_page_from_file (struct spt_entry *spte, void *kpage)
{
  /* Load the page from file. */
  acquire_filesys_lock ();
  off_t bytes_read = file_read_at (spte->file_data.file, kpage, spte->file_data.read_bytes, spte->file_data.offset);
  release_filesys_lock ();

  if (bytes_read != (off_t) spte->file_data.read_bytes)
   {
    palloc_free_page (kpage);
    return false;
   }

  /* Zero the remaining bytes. */
  memset (kpage + bytes_read, 0, spte->file_data.zero_bytes);

  /* If page is read-only, add it to the fpt for sharing.*/
  if (spte->writable == false)
    {
      fpt_add_page (
        spte->file_data.file,
        spte->file_data.offset,
        spte->upage,
        spte->file_data.read_bytes,
        spte->file_data.zero_bytes,
        (void*) vtop ((const void*) kpage)
      );
    };
  return true;
}

bool
load_page_from_swap (struct spt_entry *spte, void *kpage)
{
  /* Load the page from swap. */
  acquire_filesys_lock ();
  swap_in (kpage, spte->swap_slot);
  ASSERT (spte->checksum == frame_checksum ((void*) vtop (kpage)));
  release_filesys_lock ();
  return true;
}

bool
allocate_zero_page (void *kpage)
{
  /* Zero the page. */
  memset (kpage, 0, PGSIZE);
  return true;
}

bool
spt_set_writable (struct s_pg_table *spt, void *upage, bool writable)
{
  reentrant_lock_acquire (&spt->lock);

  struct spt_entry spte_temp;
  spte_temp.upage = pg_round_down (upage);
  struct hash_elem *e = hash_find (&spt->table, &spte_temp.elem);

  if (e == NULL)
   {
    reentrant_lock_release (&spt->lock);
    return false;
   }

  struct spt_entry *spte = hash_entry (e, struct spt_entry, elem);
  spte->writable = writable;

  reentrant_lock_release (&spt->lock);
  return true;
}

void lazy_load_spt_file (struct file *file, off_t ofs, size_t page_read_bytes, size_t page_zero_bytes, struct thread *t, uint8_t *upage, bool writable)
{
  /* Create a file_data structure to store in SPT. */
  struct file_data fdata;
  fdata.file = file;
  fdata.offset = ofs;
  fdata.read_bytes = page_read_bytes;
  fdata.zero_bytes = page_zero_bytes;

  /* Insert an SPT entry of type PAGE_FILE. */
  spt_insert_file(&t->spt, upage, &fdata, writable);
}