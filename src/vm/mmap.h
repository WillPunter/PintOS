#ifndef VM_MMAP_H
#define VM_MMAP_H
#include "filesys/file.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"
#include <debug.h>

/* Map region identifier. */
typedef int mapid_t;

/* Memory map table entry. */
struct mm_entry
  {
    mapid_t mapping;          /* Map region identifier. */
    void* addr;               /* Start address of the mapped region. */
    struct file *file;        /* File associated with the mapping. */
    struct hash_elem elem;    /* Hash element for the memory map table. */
  };

/* Memory map table. */
struct mm_table
  {
    struct hash mm;           /* Hash table. */
    int next_mid;             /* Next map region identifier. */
    struct list free_mids;    /* List of free map region identifiers. */
  };

/* Mapping element for free map region identifiers. */
struct mapping_elem
  {
    mapid_t mapping;          /* Map region identifier. */
    struct list_elem elem;    /* List element for free map region identifiers. */
  };

void mm_init (struct mm_table *mm_table);
unsigned mm_hash (const struct hash_elem *e, void *aux UNUSED);
void mm_destroy_elem (struct hash_elem * e, void *aux UNUSED);
bool mm_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
struct mm_entry *mm_entry_find (mapid_t mapping);
void mm_destroy (void);
struct mm_entry *mm_insert (void *addr, struct file *f, size_t file_size);
void mm_destroy_entry (struct thread *cur, struct mm_entry *mme);
#endif /* vm/mmap.h */