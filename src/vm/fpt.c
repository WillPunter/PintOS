#include "fpt.h"
#include "threads/synch.h"
#include <debug.h>
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/thread.h"

static struct reentrant_lock fpt_lock;
static struct hash file_page_table;

static struct fpt_page_entry *fpt_find_page_entry (struct fpt_entry *fpte, unsigned int offset, void *upage);

/* Hash function for the fpt table. Simply
   performs the file hashing function on the
   fpt entry's file pointer. */
unsigned int fpt_hash (const struct hash_elem *e, void *aux UNUSED)
{
  struct fpt_entry *fpte = hash_entry (e, struct fpt_entry, elem);
  return file_hash (fpte->file);
}

/* Comparison function for the fpt table. Returns
   the result of the file comparison function on
   the file pointers of the given elements. */
bool fpt_compare (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  struct fpt_entry *fpta = hash_entry (a, struct fpt_entry, elem);
  struct fpt_entry *fptb = hash_entry (b, struct fpt_entry, elem);

  ASSERT (fpta->file != NULL);
  ASSERT (fptb->file != NULL);
  return file_less (fpta->file, fptb->file);
}

/* Initialises the file page table and
   its corresponding lock. */
void fpt_init (void)
{
  reentrant_lock_init (&fpt_lock);
  reentrant_lock_acquire (&fpt_lock);
  hash_init (&file_page_table, fpt_hash, fpt_compare, NULL);
  reentrant_lock_release (&fpt_lock);
};

/* Add a page to the file page table */
bool fpt_add_page (
        struct file *file,
        unsigned int offset,
        void *upage,
        unsigned int read_bytes,
        unsigned int zero_bytes, 
        void *paddr
    ) {
        reentrant_lock_acquire (&fpt_lock);
    
        struct fpt_entry fpte_lookup;
        fpte_lookup.file = file;
        struct hash_elem *lookup_elem = hash_find (&file_page_table,
                                                   &fpte_lookup.elem);

        struct fpt_entry *fpte;

        if (lookup_elem == NULL)
          {
            /* No entry in fpt for given file. Create one. */
            fpte = malloc (sizeof (struct fpt_entry));
            ASSERT (fpte != NULL);

            fpte->file = file;
            list_init (&fpte->page_list);
            hash_insert (&file_page_table, &fpte->elem);
          }
        else
          {
            fpte = hash_entry (lookup_elem, struct fpt_entry, elem);
          }
        
        /* fpte now points to a valid hash table entry.
           Search for an element for the current page in
           said list. */

        struct list_elem *cur = list_begin (&fpte->page_list);
        bool found = false;

        while (cur != list_end (&fpte->page_list) && !found)
          {
            struct list_elem *next = list_next (cur);

            struct fpt_page_entry *pe = list_entry (cur, struct fpt_page_entry, elem);

            /* Check if element is correct. */
            if (pe->offset == offset && pe->upage == upage)
              {
                pe->read_bytes = read_bytes;
                pe->zero_bytes = zero_bytes;
                pe->paddr = paddr;
                found = true;
              }

            cur = next;
          }
        
        /* Check if page could not be found in list 
           and add it to list if so. */
        if (!found)
          {
            struct fpt_page_entry *pe
              = malloc (sizeof (struct fpt_page_entry));

            ASSERT (pe != NULL);

            pe->offset = offset;
            pe->upage = upage;
            pe->read_bytes = read_bytes;
            pe->zero_bytes = zero_bytes;
            pe->paddr = paddr;
            
            list_push_back (&fpte->page_list, &pe->elem);
          }

        reentrant_lock_release (&fpt_lock);
        return true;
    };

/* Remove a file and all of its corresponding pages. */
bool fpt_remove_file (struct file *file)
{
  reentrant_lock_acquire (&fpt_lock);

  /* Check that file is in fpt. */
  struct fpt_entry fpte_lookup;
  fpte_lookup.file = file;

  struct hash_elem *e = hash_find (&file_page_table, &fpte_lookup.elem);

  if (e != NULL)
    {
      struct fpt_entry *fpte = hash_entry (e, struct fpt_entry, elem);

      /* Iterate through list of fpte and remove elements. */
      while (!list_empty (&fpte->page_list))
        {
          struct list_elem *le = list_pop_back (&fpte->page_list);
          struct fpt_page_entry *pe = list_entry (le, struct fpt_page_entry, elem);
          free (pe);
        }
      
      /* Delete and free hash table element. */
      struct hash_elem *e_del = hash_delete (&file_page_table, e);
      struct fpt_entry *fpte_del = hash_entry (e_del, struct fpt_entry, elem);
      free (fpte_del);
    }
  
  reentrant_lock_release (&fpt_lock);
  return true;
}

/* Remove a page given a file and an offset. */
bool fpt_remove_page (struct file *file, unsigned int offset, void *upage)
{
  reentrant_lock_acquire (&fpt_lock);

  bool was_removed = false;

  struct fpt_entry fpte_lookup;
  fpte_lookup.file = file;

  struct hash_elem *e = hash_find (&file_page_table,
                                    &fpte_lookup.elem);

  ASSERT (file == thread_current ()->source_file);

  if (e != NULL)
    {
      /* We have found an element corresponding to the file.
          Now search the element's list of pages for one
          with the correct offset. */
      struct fpt_entry *fpte = hash_entry (e, struct fpt_entry, elem);

      struct fpt_page_entry *pe = fpt_find_page_entry (fpte, offset, upage);

      if (pe != NULL) 
        {
          list_remove (&pe->elem);
          free (pe);
          was_removed = true;
        }
      
      /* If the list is empty, remove the hash entry. */
      if (list_empty (&fpte->page_list))
        {
          hash_delete (&file_page_table, e);
          free (fpte);
        }
    }

  reentrant_lock_release (&fpt_lock);

  return was_removed;
};

/* Look up fpt_entry with corresponding file. */
struct fpt_entry *fpt_lookup (struct file *file)
{
  reentrant_lock_acquire (&fpt_lock);

  struct fpt_entry fpte_lookup;
  fpte_lookup.file = file;

  struct hash_elem *e = hash_find (&file_page_table, &fpte_lookup.elem);

  struct fpt_entry *fpte = NULL;
  
  if (e != NULL)
    {
      fpte = hash_entry (e, struct fpt_entry, elem);
    }

  reentrant_lock_release (&fpt_lock);

  return fpte;
}

/* Look up specific page given file and offset. */
struct fpt_page_entry *fpt_page_lookup (struct file *file, unsigned int offset, void *upage)
{
  reentrant_lock_acquire (&fpt_lock);

  struct fpt_entry *fpte = fpt_lookup (file);

  if (fpte == NULL)
    {
      reentrant_lock_release (&fpt_lock);
      return NULL;
    }

  /* Search fpte list for page with given offset and upage. */
  struct fpt_page_entry *pe_result = fpt_find_page_entry (fpte, offset, upage);
  reentrant_lock_release (&fpt_lock);

  return pe_result;
}

/* Find a page entry in a given fpte. */
static struct fpt_page_entry *fpt_find_page_entry (struct fpt_entry *fpte, unsigned int offset, void *upage) 
{
  struct list_elem *cur = list_begin (&fpte->page_list);

  while (cur != list_end (&fpte->page_list)) 
    {
      struct fpt_page_entry *pe = list_entry (cur, struct fpt_page_entry, elem);

      if (pe->offset == offset && pe->upage == upage) 
        {
          return pe;
        }

      cur = list_next (cur);
    }

  return NULL;
}

void relinquish_file_page_table_lock (void)
{
  reentrant_lock_relinquish (&fpt_lock);
};