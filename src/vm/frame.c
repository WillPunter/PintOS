#include "vm/frame.h"
#include <debug.h>
#include <stdio.h>
#include "devices/rtc.h"
#include "devices/swap.h"
#include "fpt.h"
#include "lib/kernel/bitmap.h"
#include "lib/random.h"
#include "page.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

#define EVICTION_SELECTION_COUNT 3

static struct hash frame_table;
static struct reentrant_lock frame_table_lock;
static void filter_frame_owner_list (struct list *list, bool (*filter)(struct frame_owner *, void *), void *aux);
static void ft_destroy_elem (struct hash_elem *element, void *aux UNUSED);
static bool ft_remove_filter (struct frame_owner *fo, void *owner);
void evict (void);
static struct frame_table_entry * select_eviction_frame (void);
static void evict_page (struct frame_table_entry *chosen_page);

/* Initialises frame table. */
void ft_init (void)
{
  /* Initialise frame table lock. */
  reentrant_lock_init (&frame_table_lock);

  acquire_frame_table_lock ();
  hash_init (&frame_table, ft_hash, ft_less, NULL);
  release_frame_table_lock ();
}

/* Hash function for supplemental page table. */
unsigned ft_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct frame_table_entry *fte = hash_entry (e, struct frame_table_entry, elem);
  return hash_bytes (&fte->phys_addr, sizeof fte->phys_addr);
}

/* Comparison function for frame table. */
bool
ft_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct frame_table_entry *fte_a = hash_entry (a, struct frame_table_entry, elem);
  const struct frame_table_entry *fte_b = hash_entry (b, struct frame_table_entry, elem);

  return fte_a->phys_addr < fte_b->phys_addr;
}

 /* Finds and returns the supplemental page table entry for the given virtual address. */
struct frame_table_entry *
ft_entry_find (void *phys_addr)
{
  acquire_frame_table_lock ();

  struct frame_table_entry ft_temp;
  struct hash_elem *e;

  /* Initialize a temporary spt_entry with the page-aligned address. */
  ft_temp.phys_addr = pg_round_down (phys_addr);
  e = hash_find (&frame_table, &ft_temp.elem);
  
  struct frame_table_entry * result = NULL;
  
  if (e != NULL)
      result = hash_entry (e, struct frame_table_entry, elem);
  
  release_frame_table_lock ();

  return result;
}

/* Filters a list of frame_owner structures, removing those that do not
   pass the provided filter function. */
static void filter_frame_owner_list (struct list *list, bool (*filter)(struct frame_owner *, void *), void *aux)
{
  struct list_elem *cur = list_begin (list);

  while (cur != list_end (list))
    {
      struct list_elem *next = cur->next;
      struct frame_owner *owner = list_entry (cur, struct frame_owner, elem);

      if (filter == NULL || !filter (owner, aux))
        {
          list_remove (cur);
          free (owner);
        }
      
      cur = next;
    }
}

/* Destroy a frame table entry by freeing each of
   the owner structures. */
static void ft_destroy_elem (struct hash_elem *element, void *aux UNUSED)
{
  struct frame_table_entry * fte = hash_entry (element, struct frame_table_entry, elem);
  filter_frame_owner_list (&fte->owner_list, NULL, NULL);
  free (fte);
}

/* Destroy frame table and all lists contained in it. */
void ft_destroy (void)
{   
  acquire_frame_table_lock ();
  hash_destroy (&frame_table, ft_destroy_elem);
  release_frame_table_lock ();
}

/* Filter by owner - remove elements that are owned by
   the supplied owner thread. */
static bool ft_remove_filter (struct frame_owner *fo, void *owner)
{
  return fo->owner != (struct thread *) owner;
}

/* Removes the mapping from the given physical
   address that belongs to the owner thread. Returns
   true if the hash element was deleted (i.e. no more owners).
   Returns false otherwise. */
bool ft_remove (void *paddr, struct thread *owner)
{
  acquire_frame_table_lock ();
  bool result = false;
  struct frame_table_entry *fte = ft_entry_find (paddr);

  /* Only try to remove if the given paddr actually
     corresponds to an element. */
  if (fte != NULL)
    {
      /* There is a hash table element that corresponds to
        the given physical address. Filter out all elements
        that are owned by the current thread. */
      filter_frame_owner_list (&fte->owner_list, ft_remove_filter, (void*) owner);

      /* Check the length of the new list. */
      if (list_empty (&fte->owner_list))
        {
          hash_delete (&frame_table, &fte->elem);
          free (fte);
          result = true;
        }
    }

  release_frame_table_lock ();
  return result;
}

/* Inserts a mapping from the given virtual address
   to the given physical address to the frame table.
   The current thread is assumed to be the owner of
   the given user page. */
void ft_insert (void *vaddr, void *paddr)
{
  acquire_frame_table_lock ();
  struct frame_table_entry *fte;
  struct frame_owner *ft_frame_owner = malloc (sizeof (struct frame_owner));

  if (ft_entry_find (paddr) == NULL)
    {
      /* There is not currently a frame_table_entry
      corresponding to this physical address in
      the frame table, so we allocate a new one. */

      fte = malloc (sizeof (struct frame_table_entry));
      fte->phys_addr = paddr;  /* Set the physical address. */
      fte->pinned = false;
      list_init (&fte->owner_list);
      hash_insert (&frame_table, &fte->elem);
    }
  else
    {
      /* There is already a frame_table_entry for
      the current physical address so we can
      simply look it up. */
      fte = ft_entry_find (paddr);
    }

  ft_frame_owner->vaddr = vaddr;
  ft_frame_owner->owner = thread_current ();
  list_push_front (&fte->owner_list, &ft_frame_owner->elem);
  release_frame_table_lock ();
}

/* Acquire the frame lock. */
void acquire_frame_table_lock (void)
{
  reentrant_lock_acquire (&frame_table_lock);
}

/* Releasing the frame table lock. */
void release_frame_table_lock (void)
{
  reentrant_lock_release (&frame_table_lock);
}

/* Relinquish the frame table lock. */
void relinquish_frame_table_lock (void)
{
  reentrant_lock_relinquish (&frame_table_lock);
}

/* Allocate user page - get a frame of physical
   memory and install it at the given user address
   in the page table. It returns the kernel virtual
   address of the newly created page. */
void *allocate_user_page (void *upage, bool writable)
{
  acquire_frame_table_lock ();
  void *kpage = obtain_frame (upage);
  ASSERT (kpage != NULL);

  /* Install page in process' page table. */
  if (!install_page (upage, kpage, writable))
    {
      palloc_free_page (kpage);
      return NULL;
    };

  /* Install page metadata in supplemental
      page table. */
  spt_insert_frame (&thread_current ()->spt, upage, writable);
  release_frame_table_lock ();
  return kpage;
}

/* Evict. */
void evict (void)
{
  acquire_frame_table_lock ();
  struct frame_table_entry *chosen_page = select_eviction_frame ();
  evict_page (chosen_page);
  release_frame_table_lock ();
}

static unsigned int choice = 0;

/* Select and return a page for eviction. I.e. implement
   an eviection policy. */
static struct frame_table_entry * select_eviction_frame (void)
{
  acquire_frame_table_lock ();
  unsigned int counter = 0;
  choice = choice % ft_size ();
  struct hash_iterator cur;

  hash_first (&cur, &frame_table);
  struct hash_elem *e = hash_next (&cur);
  struct frame_table_entry *selection = hash_entry (e, struct frame_table_entry, elem);
  struct frame_owner *owner = list_entry (list_begin (&selection->owner_list), struct frame_owner, elem);

  while ((counter < choice || selection->pinned || pagedir_is_accessed (owner->owner->pagedir, owner->vaddr)))
    {
      if (counter >= choice && !selection->pinned && pagedir_is_accessed (owner->owner->pagedir, owner->vaddr)) 
        {
          pagedir_set_accessed (owner->owner->pagedir, owner->vaddr, false);
          pagedir_set_accessed (owner->owner->pagedir, ptov ((uintptr_t) selection->phys_addr), false);
        }

      e = hash_next (&cur);
      if (e == NULL)
        {
          hash_first (&cur, &frame_table);
          e = hash_next (&cur);
        }
      selection = hash_entry (e, struct frame_table_entry, elem);
      owner = list_entry (list_begin (&selection->owner_list), struct frame_owner, elem);

      counter ++;

      /* If there are no frames to evict */
      if (counter >= (EVICTION_SELECTION_COUNT * ft_size ()))
        {
          thread_exit ();
        }

    }

  choice = counter + 1;    
  release_frame_table_lock ();
  return selection;
}

/* Evict the given page.
  If a page is unwritten to and is not a stack
  page, then it can be removed (it can just
  read back from file). */

static void evict_page (struct frame_table_entry *chosen_page)
{
  acquire_frame_table_lock ();

  /* Remove references to the frame from any page
      table that refers to it - iterate through all
      owners and remove. */
  struct list_elem *cur = list_begin (&chosen_page->owner_list);

  enum PAGE_DATA_TYPE page_destination = PAGE_ERROR;
  bool has_file = false;
  size_t swap_slot;

  /* Compute frame checksum. */
  uint32_t ck = frame_checksum (chosen_page->phys_addr);

  /* Determine whether it is to be swapped to the
    swap buffer or simply erased. We iterate through 
    all owners. If any of their dirty bits are set
    (or it is a stack frame) then we swap to buffer, 
    otherwise we to file or zero. */

  while (cur != list_end (&chosen_page->owner_list))
    {
      struct frame_owner *fo = list_entry (cur, struct frame_owner, elem);

      reentrant_lock_acquire (&fo->owner->spt.lock);

      if (pagedir_is_dirty (fo->owner->pagedir, fo->vaddr))
        {
          page_destination = PAGE_SWAP;
        }
      
      struct spt_entry *spte = spt_entry_find (&fo->owner->spt, fo->vaddr);
      spte->checksum = ck;

      if (page_destination == PAGE_ERROR)
        {
          if (spte->file_data.file != NULL)
            {
              has_file = true;
            }
        }
      
      reentrant_lock_release (&fo->owner->spt.lock);
      cur = cur->next;
    }

  if (page_destination != PAGE_SWAP)
    {
      if (has_file)
        {
          page_destination = PAGE_FILE;
        }
      else
        {
          page_destination = PAGE_ZERO;
        }
    }
  else
    {
      acquire_filesys_lock ();
      swap_slot = swap_out (ptov ((uintptr_t) chosen_page->phys_addr));
      release_filesys_lock ();

      if (swap_slot == BITMAP_ERROR)
        {
          PANIC ("Swap Disk Full!\n");
        }
    }

  ASSERT (page_destination != PAGE_ERROR);

  /* Remove references to swapped out frame from
      various data structures. */
  cur = list_begin (&chosen_page->owner_list);

  struct file *page_file = NULL;
  unsigned int offset = 0;
  void *uaddr = NULL;

  while (cur != list_end (&chosen_page->owner_list))
    {
      struct list_elem *next = cur->next;
      struct frame_owner *fo = list_entry (cur, struct frame_owner, elem);
      reentrant_lock_acquire (&fo->owner->spt.lock);

      /* Remove page from pagedir. */
      pagedir_clear_page (fo->owner->pagedir, fo->vaddr);

      /* Mark spt entry as swapped. */
      struct spt_entry *spte = spt_entry_find (&fo->owner->spt, fo->vaddr);
      spte->type = page_destination;

      if (page_destination == PAGE_SWAP)
        {
          spte->swap_slot = swap_slot;
        }

      page_file = spte->file_data.file;
      offset = spte->file_data.offset;
      uaddr = spte->upage;

      reentrant_lock_release (&fo->owner->spt.lock);

      /* Remove from list. */
      list_remove (cur);
      free (fo);
      cur = next;
    }
  
  if (page_file != NULL && uaddr != NULL)
    {
      fpt_remove_page (page_file, offset, uaddr);
    }

  palloc_free_page (ptov ((uintptr_t) chosen_page->phys_addr));
  release_frame_table_lock ();
}

/* Get the frame table size */
size_t ft_size (void)
{
  return hash_size (&frame_table);
}

uint32_t frame_checksum (void *phys_addr)
{
  void *kpage = ptov ((uintptr_t) pg_round_down (phys_addr));
  uint32_t total = 0;

  for (uint8_t *ptr = kpage; ptr < (uint8_t*) kpage + PGSIZE; ptr++)
    {
      total += *ptr;
    }
  
  return total;
}

void*
obtain_frame (void *upage)
{
  acquire_frame_table_lock ();
  void *kpage = palloc_get_page (PAL_USER);
  while (kpage == NULL)
    {
      evict ();
      barrier ();
      kpage = palloc_get_page (PAL_USER);
    }

  /* Add the frame to the frame table. */
  void *phys_addr = (void *) vtop (kpage);
  ft_insert (upage, phys_addr);
  release_frame_table_lock ();
  return kpage;
}