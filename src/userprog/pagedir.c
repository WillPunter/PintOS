#include "userprog/pagedir.h"
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/palloc.h"
#include "vm/frame.h"
#include "vm/fpt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include <stdio.h>

static uint32_t *active_pd (void);
static void invalidate_pagedir (uint32_t *);
static void unshare_current_thread_page (uint32_t *pd,
                                         const void *upage,
                                         struct thread *writer_thread);

/* Creates a new page directory that has mappings for kernel
   virtual addresses, but none for user virtual addresses.
   Returns the new page directory, or a null pointer if memory
   allocation fails. */
uint32_t *
pagedir_create (void) 
{
  uint32_t *pd = palloc_get_page (0);
  if (pd != NULL)
    memcpy (pd, init_page_dir, PGSIZE);
  return pd;
}

/* We have an issue here, with synchronising the frame table
   and page directory. When we call spt_destroy, we delete the
   frame table.*/

/* Destroys page directory PD, freeing all the pages it
   references. This must now be modified to prevent
   the deletion of pages in memory when sharing. */
void
pagedir_destroy (uint32_t *pd) 
{
  uint32_t *pde;

  if (pd == NULL)
    return;

  ASSERT (pd != init_page_dir);
  for (pde = pd; pde < pd + pd_no (PHYS_BASE); pde++)
    {
      if (*pde & PTE_P) 
        {
          uint32_t *pt = pde_get_pt (*pde);
          uint32_t *pte;
          
          for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++)
            {
              if (*pte & PTE_P)
                {
                  palloc_free_page (pte_get_page (*pte));
                }
            }
          palloc_free_page (pt);
        }
    }
  palloc_free_page (pd);
}

/* Returns the address of the page table entry for virtual
   address VADDR in page directory PD.
   If PD does not have a page table for VADDR, behavior depends
   on CREATE.  If CREATE is true, then a new page table is
   created and a pointer into it is returned.  Otherwise, a null
   pointer is returned. */
static uint32_t *
lookup_page (uint32_t *pd, const void *vaddr, bool create)
{
  uint32_t *pt, *pde;

  ASSERT (pd != NULL);

  /* Shouldn't create new kernel virtual mappings. */
  ASSERT (!create || is_user_vaddr (vaddr));

  /* Check for a page table for VADDR.
     If one is missing, create one if requested. */
  pde = pd + pd_no (vaddr);
  if (*pde == 0) 
    {
      if (create)
        {
          pt = palloc_get_page (PAL_ZERO);
          if (pt == NULL) 
            return NULL; 
      
          *pde = pde_create (pt);
        }
      else
        return NULL;
    }

  /* Return the page table entry. */
  pt = pde_get_pt (*pde);
  return &pt[pt_no (vaddr)];
}

/* Adds a mapping in page directory PD from user virtual page
   UPAGE to the physical frame identified by kernel virtual
   address KPAGE.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   If WRITABLE is true, the new page is read/write;
   otherwise it is read-only.
   Returns true if successful, false if memory allocation
   failed. */
bool
pagedir_set_page (uint32_t *pd, void *upage, void *kpage, bool writable)
{
  uint32_t *pte;

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (pg_ofs (kpage) == 0);
  ASSERT (is_user_vaddr (upage));
  ASSERT (vtop (kpage) >> PTSHIFT < init_ram_pages);
  ASSERT (pd != init_page_dir);

  pte = lookup_page (pd, upage, true);

  if (pte != NULL) 
    {
      ASSERT ((*pte & PTE_P) == 0);
      *pte = pte_create_user (kpage, writable);
      return true;
    }
  else
    return false;
}

/* Looks up the physical address that corresponds to user virtual
   address UADDR in PD.  Returns the kernel virtual address
   corresponding to that physical address, or a null pointer if
   UADDR is unmapped. */
void *
pagedir_get_page (uint32_t *pd, const void *uaddr) 
{
  uint32_t *pte;

  ASSERT (is_user_vaddr (uaddr));
  
  pte = lookup_page (pd, uaddr, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    return pte_get_page (*pte) + pg_ofs (uaddr);
  else
    return NULL;
}

/* Marks user virtual page UPAGE "not present" in page
   directory PD.  Later accesses to the page will fault.  Other
   bits in the page table entry are preserved.
   UPAGE need not be mapped. */
void
pagedir_clear_page (uint32_t *pd, void *upage) 
{
  uint32_t *pte;

  ASSERT (pg_ofs (upage) == 0);
  ASSERT (is_user_vaddr (upage));

  pte = lookup_page (pd, upage, false);
  if (pte != NULL && (*pte & PTE_P) != 0)
    {
      *pte &= ~PTE_P;
      invalidate_pagedir (pd);
    }
}

/* Returns true if the PTE for virtual page VPAGE in PD is dirty,
   that is, if the page has been modified since the PTE was
   installed.
   Returns false if PD contains no PTE for VPAGE. */
bool
pagedir_is_dirty (uint32_t *pd, const void *vpage) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_D) != 0;
}

/* Given a page directory and a user page, checks if the given pd
   is that of the current thread. If so, it removes any entries
   in the fpt corresponding to the user page given from the fpt.
   It also replaces the spt entries for all sharing pages to files,
   so that they lazily load the page they were previously sharing
   back into memory when they next try to access the previously shared
   page. */
static void
unshare_current_thread_page (uint32_t *pd, const void *upage, struct thread *writer_thread)
  {
    enum intr_level old_level = intr_disable ();
    ASSERT (pg_ofs (upage) == 0);

    /* Locate supplemental page table entry for the vpage.
      If the page was loaded from a file then we want to
      check if it was shared, and if so we want to stop
      sharing. This involves removing the shared page from
      the page table of all owners and set their spt entries
      to read from the file instead. */
    acquire_frame_table_lock ();
        
    void *kpage = pagedir_get_page (pd, upage);

    struct frame_table_entry *fte = ft_entry_find ((void*) vtop (kpage));

    struct list_elem *e = list_begin (&fte->owner_list);

    struct thread *owner_thread = NULL;

    while (e != list_end (&fte->owner_list))
      {
        struct list_elem *next = e->next;

        struct frame_owner *fo = list_entry (e, struct frame_owner, elem);

        owner_thread = fo->owner;

        if (writer_thread == NULL ||
            (writer_thread != NULL && fo->owner != writer_thread))
          {
            reentrant_lock_acquire (&owner_thread->spt.lock);

            struct spt_entry *owner_spte = spt_entry_find (&fo->owner->spt, fo->vaddr);

            /* Only pages loaded from executable files can be
               shared */
            if (owner_spte->file_data.file != NULL)
              {
                /* If these assertions fail then the spte and frame table are out of synch.
                    This case should never occur. */
                ASSERT (owner_spte == NULL);
                ASSERT (owner_spte->type == PAGE_FRAME);
                ASSERT (owner_spte->file_data.file != NULL);

                owner_spte->type = PAGE_FILE;

                /* Since page is no longer read-only, get rid of all owners
                  who share the page. Remove the page from their page directories */
                pagedir_clear_page (fo->owner->pagedir, fo->vaddr);
                list_remove (e);

                free (fo);
              }
            reentrant_lock_release (&owner_thread->spt.lock);
          }

        e = next;
      }

    if (owner_thread != NULL)
      {
        reentrant_lock_acquire (&owner_thread->spt.lock);
        struct spt_entry *spte = spt_entry_find (&owner_thread->spt, (void*) upage);

        if (spte->file_data.file != NULL)
          {
            fpt_remove_page (spte->file_data.file, spte->file_data.offset, spte->upage);
          }

        reentrant_lock_release (&owner_thread->spt.lock);
      }

    release_frame_table_lock ();
    intr_set_level (old_level);
  }

/* Set the dirty bit to DIRTY in the PTE for virtual page VPAGE
   in PD. */
void
pagedir_set_dirty (uint32_t *pd, const void *vpage, bool dirty) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (dirty)
        { 
          *pte |= PTE_D;

          unshare_current_thread_page (pd, vpage, thread_current ());
        }
      else 
        {
          *pte &= ~(uint32_t) PTE_D;
          invalidate_pagedir (pd);
        }
    }
}

/* Returns true if the PTE for virtual page VPAGE in PD has been
   accessed recently, that is, between the time the PTE was
   installed and the last time it was cleared.  Returns false if
   PD contains no PTE for VPAGE. */
bool
pagedir_is_accessed (uint32_t *pd, const void *vpage) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_A) != 0;
}

/* Sets the accessed bit to ACCESSED in the PTE for virtual page
   VPAGE in PD. */
void
pagedir_set_accessed (uint32_t *pd, const void *vpage, bool accessed) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (accessed)
        *pte |= PTE_A;
      else 
        {
          *pte &= ~(uint32_t) PTE_A; 
          invalidate_pagedir (pd);
        }
    }
}

/* Returns true if the PTE for virtual page VPAGE in PD is writable.
   Returns false if PD contains no PTE for VPAGE. */
bool
pagedir_is_writable (uint32_t *pd, const void *vpage) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  return pte != NULL && (*pte & PTE_W) != 0;
}

/* Set the writable bit to WRITABLE in the PTE for virtual page VPAGE
   in PD. */
void
pagedir_set_writable (uint32_t *pd, const void *vpage, bool writable) 
{
  uint32_t *pte = lookup_page (pd, vpage, false);
  if (pte != NULL) 
    {
      if (writable)
        {
          /* Set writable bit in page table entry */
          *pte |= PTE_W;

          unshare_current_thread_page (pd, vpage, thread_current ());
        }
      else 
        {
          *pte &= ~(uint32_t) PTE_W;
          invalidate_pagedir (pd);
        }
    }
}

/* Loads page directory PD into the CPU's page directory base
   register. */
void
pagedir_activate (uint32_t *pd) 
{
  if (pd == NULL)
    pd = init_page_dir;

  /* Store the physical address of the page directory into CR3
     aka PDBR (page directory base register).  This activates our
     new page tables immediately.  See [IA32-v2a] "MOV--Move
     to/from Control Registers" and [IA32-v3a] 3.7.5 "Base
     Address of the Page Directory". */
  asm volatile ("movl %0, %%cr3" : : "r" (vtop (pd)) : "memory");
}

/* Returns the currently active page directory. */
static uint32_t *
active_pd (void) 
{
  /* Copy CR3, the page directory base register (PDBR), into
     `pd'.
     See [IA32-v2a] "MOV--Move to/from Control Registers" and
     [IA32-v3a] 3.7.5 "Base Address of the Page Directory". */
  uintptr_t pd;
  asm volatile ("movl %%cr3, %0" : "=r" (pd));
  return ptov (pd);
}

/* Some page table changes can cause the CPU's translation
   lookaside buffer (TLB) to become out-of-sync with the page
   table.  When this happens, we have to "invalidate" the TLB by
   re-activating it.

   This function invalidates the TLB if PD is the active page
   directory.  (If PD is not active then its entries are not in
   the TLB, so there is no need to invalidate anything.) */
static void
invalidate_pagedir (uint32_t *pd) 
{
  if (active_pd () == pd) 
    {
      /* Re-activating PD clears the TLB.  See [IA32-v3a] 3.12
         "Translation Lookaside Buffers (TLBs)". */
      pagedir_activate (pd);
    } 
}
