#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <stddef.h>
#include <debug.h>
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/synch.h"

enum PAGE_DATA_TYPE {
    PAGE_FRAME,
    PAGE_FILE,
    PAGE_SWAP,
    PAGE_ZERO,
    PAGE_ERROR
};

struct file_data {
    struct file* file;                   /* File pointer. */
    off_t offset;                        /* Offset in the file. */
    uint32_t read_bytes;                 /* Number of bytes to read. */
    uint32_t zero_bytes;                 /* Number of zero bytes to add. */
};

struct spt_entry {
    void* upage;                        /* User virtual address. */
    enum PAGE_DATA_TYPE type;           /* Type of the page. */
    struct hash_elem elem;              /* Hash element. */
    struct file_data file_data;         /* File associated with the page. */
    size_t swap_slot;                   /* Swap slot number. */
    bool writable;                      /* Is the page writable? */
    uint32_t checksum;
};

/* Supplemental page table - combines a hash table with its own lock
   to allow for easier synchronisation. */
struct s_pg_table {
    struct hash table;
    struct reentrant_lock lock;
};

void spt_init (struct s_pg_table *pt);
unsigned spt_hash (const struct hash_elem *e, void *aux UNUSED);
bool spt_less (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
struct spt_entry *spt_entry_find (struct s_pg_table *spt, void *upage);
void spt_destroy (struct s_pg_table *spt);
bool spt_insert_frame (struct s_pg_table *spt, void *upage, bool writable);
bool spt_insert_file (struct s_pg_table *spt, void *upage, struct file_data *file_data, bool writable);
bool spt_insert_swap (struct s_pg_table *spt, void *upage, size_t swap_slot, bool writable);
bool spt_insert_zero (struct s_pg_table *spt, void *upage, bool writable);
bool load_page (struct spt_entry *spte);
bool load_page_from_file (struct spt_entry *spte, void *kpage);
bool load_page_from_swap (struct spt_entry *spte, void *kpage);
bool allocate_zero_page (void *kpage);
bool spt_set_writable (struct s_pg_table *spt, void *upage, bool writable);
void lazy_load_spt_file (struct file *file, off_t ofs, size_t page_read_bytes, size_t page_zero_bytes, struct thread *t, uint8_t *upage, bool writable);
#endif /* vm/page.h */