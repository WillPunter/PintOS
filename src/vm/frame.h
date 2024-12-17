#ifndef FRAME_H
#define FRAME_H

#include "lib/kernel/list.h"
#include "threads/synch.h"
#include "lib/kernel/hash.h"
#include <debug.h>

/* Frame Table Entry - each element of the
   hash table corresponds to one of these
   structures, storing the physical address
   as well as a list of threads that own
   the frame. */
struct frame_table_entry
  {
    void *phys_addr;                /* Physical address of the frame - serves as the key. */
    struct list owner_list;         /* List of threads that own / share the frame. */
    struct hash_elem elem;          /* Hash element to allow insertion in hash table. */
    bool pinned;                    /* is the frame pinned?. */
  };

/* Frame owner struct - each hash table entry
   stores a list of these. */
struct frame_owner
  {
    void *vaddr;                      /* Address of page in user virtual memory. */
    struct thread *owner;             /* Process that owns said page. */
    struct list_elem elem;            /* List element. */
  };

void ft_init (void);
unsigned ft_hash (const struct hash_elem *e, void *aux);
bool ft_less (const struct hash_elem *a, const struct hash_elem *b, void *aux);
struct frame_table_entry *ft_entry_find (void *phys_addr);
void ft_destroy (void);
void ft_insert (void *vaddr, void *phys_addr);
void *allocate_user_page (void *upage, bool writable);
bool ft_remove (void *paddr, struct thread *owner);
void* obtain_frame (void *upage);
size_t ft_size (void);
void acquire_frame_table_lock (void);
void release_frame_table_lock (void);
void relinquish_frame_table_lock (void);
uint32_t frame_checksum (void *phys_addr);

#endif /* vm/frame.h */