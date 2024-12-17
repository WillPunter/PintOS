#include "vm/mmap.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "threads/synch.h"
#include "vm/frame.h"
#include "mmap.h"

static int get_mapping_id (struct mm_table *mm_table);
static void handle_page (void *kpage, struct thread *cur, void *upage, struct mm_entry *mme, struct spt_entry *spte);
static void free_frame (void *kpage, struct thread *cur);
static void write_back_dirty_page (void *upage, struct mm_entry *mme, struct spt_entry *spte);
static void remove_spt_entry (struct s_pg_table *spt, struct spt_entry *spte);
static void remove_mapping_entry (struct thread *cur, struct mm_entry *mme);

/* Initializes the memory map table - creates a corresponding
  hash table and lock and initialises next map id to map. */
void
mm_init (struct mm_table *mm_table) 
{
  hash_init (&mm_table->mm, mm_hash, mm_less, NULL);
  list_init (&mm_table->free_mids);
  mm_table->next_mid = 0;
}

/* Hash function for memory map table. */
unsigned
mm_hash (const struct hash_elem *e, void *aux UNUSED)
{
  const struct mm_entry *mme = hash_entry (e, struct mm_entry, elem);
  return hash_int (mme->mapping);
}

/* Comparison function for memory map table. */
bool
mm_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  const struct mm_entry *mme_a = hash_entry (a, struct mm_entry, elem);
  const struct mm_entry *mme_b = hash_entry (b, struct mm_entry, elem);
  return mme_a->mapping < mme_b->mapping;
}

/* Finds and returns the memory map table entry for the given address. */
struct mm_entry *
mm_entry_find (mapid_t mapping)
{
  struct mm_table *mm_table = &thread_current ()->mm_table;
  struct mm_entry mme_temp;
  struct hash_elem *e;

  /* Initialize a temporary mm_entry with the mapid. */
  mme_temp.mapping = mapping;
  e = hash_find (&mm_table->mm, &mme_temp.elem);

  struct mm_entry *result;

  if (e == NULL)
   result = NULL;
  else
   result = hash_entry (e, struct mm_entry, elem);

  return result;
}

/* Free a given element from a memory map table. */
void
mm_destroy_elem (struct hash_elem *e, void *aux UNUSED)
{
  struct mm_entry *mme = hash_entry (e, struct mm_entry, elem);
  mm_destroy_entry (thread_current (), mme);
}

/* Free a memory map table including all of its elements. */
void
mm_destroy (void)
{
  struct mm_table *mm_table = &thread_current ()->mm_table;
  hash_destroy (&mm_table->mm, mm_destroy_elem);
  struct list_elem *e;
  while (!list_empty (&mm_table->free_mids))
   {
    e = list_pop_front (&mm_table->free_mids);
    free (list_entry (e, struct mapping_elem, elem));
   }
}

void
mm_destroy_entry (struct thread *cur, struct mm_entry *mme)
{
  struct s_pg_table *spt = &cur->spt;
  size_t offset;
  size_t file_size = file_length (mme->file);

  for (offset = 0; offset < file_size; offset += PGSIZE)
   {
    void *upage = mme->addr + offset;
    reentrant_lock_acquire (&spt->lock);
    struct spt_entry *spte = spt_entry_find (spt, upage);
    if (spte == NULL)
      continue; /* Page may have been already unmapped. */

    void *kpage = pagedir_get_page (cur->pagedir, upage);
    if (kpage != NULL)
      handle_page (kpage, cur, upage, mme, spte);

    remove_spt_entry (spt, spte);
    reentrant_lock_release (&spt->lock);
   }

  file_close (mme->file);
  remove_mapping_entry (cur, mme);
}

/* Remove the mapping entry from the mapping table. */
static void
remove_mapping_entry (struct thread *cur, struct mm_entry *mme)
{
  struct mm_table *mm_table = &cur->mm_table;
  struct mapping_elem *mid = malloc (sizeof (struct mapping_elem));
  mid->mapping = mme->mapping;
  list_insert (list_end (&mm_table->free_mids), &mid->elem);
  hash_delete (&mm_table->mm, &mme->elem);
  free (mme);
}

/* Remove the spt_entry from supplemental page table. */
static void
remove_spt_entry (struct s_pg_table *spt, struct spt_entry *spte)
{
  reentrant_lock_acquire (&spt->lock);
  hash_delete (&spt->table, &spte->elem);
  reentrant_lock_release (&spt->lock);
  free (spte);
}

static void
handle_page (void *kpage, struct thread *cur, void *upage, struct mm_entry *mme, struct spt_entry *spte)
{
  /* Check if page is dirty. */
  if (pagedir_is_dirty (cur->pagedir, upage))
   write_back_dirty_page (upage, mme, spte);
  /* Remove the page from page directory. */
  pagedir_clear_page (cur->pagedir, upage);
  free_frame (kpage, cur);
}

/* Free the frame and remove the frame entry from the frame table. */
static void
free_frame (void *kpage, struct thread *cur)
{
  void *paddr = (void *) vtop (kpage);
  ft_remove (paddr, cur);
  palloc_free_page (kpage);
}

/* Write back to the file. */
static void
write_back_dirty_page (void *upage, struct mm_entry *mme, struct spt_entry *spte)
{
  acquire_filesys_lock ();
  file_write_at (mme->file, upage, spte->file_data.read_bytes, spte->file_data.offset);
  release_filesys_lock ();
}

/* Allocates a new mm_entry, initialises it with
  the file associated with fd, the address given,
  and the next map id to be mapped. */
struct mm_entry *
mm_insert (void *addr, struct file *f, size_t file_size)
{
  struct thread *cur = thread_current ();
  struct mm_table *mm_table = &cur->mm_table;

  struct mm_entry *mme = malloc (sizeof (struct mm_entry));
  
  ASSERT (mme != NULL);

  mme->addr = addr;
  mme->file = f;
  mme->mapping = get_mapping_id (mm_table);

  hash_insert (&mm_table->mm, &mme->elem);
  size_t offset = 0;
  size_t read_bytes = file_size;
  for (offset = 0; offset < file_size; offset += PGSIZE)
   {
    void *upage = addr + offset;

    /* Find the number of bytes to be read and that are zero. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;
    lazy_load_spt_file (f, offset, page_read_bytes, page_zero_bytes, cur, upage, true);
    read_bytes -= page_read_bytes;
   }
  return mme;
}

static int
get_mapping_id (struct mm_table *mm_table)
{
  if (!list_empty (&mm_table->free_mids))
   {
    struct mapping_elem *free_mid_entry = list_entry (list_pop_front (&mm_table->free_mids), struct mapping_elem, elem);
    mapid_t mapping_id = free_mid_entry->mapping; 
    free (free_mid_entry);
    return mapping_id;
   }
  return mm_table->next_mid++;
}
