/* fpt - file (to) page table */

#ifndef FPT_H
#define FPT_H

#include "../lib/kernel/list.h"
#include "../lib/kernel/hash.h"
#include "../filesys/file.h"
#include "../filesys/filesys.h"

/* File Page Table Entry - each element of the
   list corresponds to one of these structures,
   storing the offset in the file, the number
   of bytes to read, the number of bytes to zero,
   the user virtual address, and the physical
   address. */
struct fpt_page_entry
  {
    unsigned int offset;        /* Offset in file. */
    unsigned int read_bytes;    /* Number of bytes to read. */
    unsigned int zero_bytes;    /* Number of bytes to zero. */
    void *upage;                /* User virtual address. */
    void *paddr;                /* Physical address. */
    struct list_elem elem;      /* List element. */
  };

/* File Page Table Entry - each element of the
   hash table corresponds to one of these structures,
   storing the file and a list of file page entries. */
struct fpt_entry
  {
    struct file *file;          /* File stored by entry. */
    struct list page_list;      /* List of file page entries. */
    struct hash_elem elem;      /* Hash element to allow insertion in hash table. */
  };

unsigned int fpt_hash (const struct hash_elem *e, void *aux);
bool fpt_compare (const struct hash_elem *a, const struct hash_elem *b, void *aux);
bool fpt_add_page (struct file *file, unsigned int offset, void *upage, unsigned int read_bytes, unsigned int zero_bytes, void *paddr);
bool fpt_remove_file (struct file *file);
bool fpt_remove_page (struct file *file, unsigned int offset, void *upage);
struct fpt_entry *fpt_lookup (struct file *file);
struct fpt_page_entry *fpt_page_lookup (struct file *file, unsigned int offset, void *upage);
void fpt_init (void);
void relinquish_file_page_table_lock (void);

#endif /* vm/fpt.h */