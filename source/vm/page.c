#include "lib/kernel/list.h"
#include "threads/thread.h"
#include "page.h"
#include "swap.h"
#include "frame.h"
#include "userprog/process.h"

void page_init (void) {
	/* Init supplemental page table in userprog/process.c */
}

/* Matthew drove here */
/* Computes and returns the hash value for hash element E, given
   auxiliary data AUX. */
unsigned spt_hash_func (const struct hash_elem * elem, void * aux) {
  struct page *pg = hash_entry(elem, struct page, supp_page_table_elem);
  int int_page = (int) pg->user_vaddr;
  return hash_int(int_page);
}

/* Hash function used for comparing the user virtual addresses
  of two hash elements */
bool spt_less_func (const struct hash_elem * a,
                             const struct hash_elem * b,
                             void * aux) {
	struct page * page_a;
	struct page * page_b;
	page_a = hash_entry(a, struct page, supp_page_table_elem);
	page_b = hash_entry(b, struct page, supp_page_table_elem);

	return page_a->user_vaddr < page_b->user_vaddr;
}
/* End of Matthew driving */

/* Prajit drove here */
/* Returns the page containing the given virtual address,
   or a null pointer if no such page exists. */
struct page *page_lookup (const void *address)
{
  struct page p;
  struct hash_elem *e;

  p.user_vaddr = address;
  lock_acquire(&thread_current()->spt_lock);
  e = hash_find (&thread_current()->supp_page_table, &p.supp_page_table_elem);
  lock_release(&thread_current()->spt_lock);
  return e != NULL ? hash_entry (e, struct page, supp_page_table_elem) : NULL;
}
/* End of Prajit driving */

/* Matthew and Garrett drove here */
/* Hash helper function used for destroying supplemental page table */
void spt_action_func(struct hash_elem *e, void *aux) {
  struct page *pg = hash_entry(e, struct page, supp_page_table_elem);
  lock_acquire(&ft_lock);
  void *kpage = pagedir_get_page(pg->thr->pagedir, pg->user_vaddr);

  /* this page is still in memory, must remove it and
     clear its mapping */
  if(kpage != NULL) {
    ASSERT(list_remove(&pg->frame_table_elem) != NULL);
    lock_release(&ft_lock); 
    pagedir_clear_page(pg->thr->pagedir, pg->user_vaddr);
    palloc_free_page(kpage);
  } else
    lock_release(&ft_lock); 

  if(pg->loc == SWAP) {
    /* if the page is on swap, then we must clear its mapping
       and free the space on swap */
    lock_acquire(&swap_lock);
    bitmap_set(swap_bitmap, pg->index, 0); // unset swap entry
    lock_release(&swap_lock);
  }
  free(pg);
}

/* Function used to allocate extra pages to the stack. If there
   is not an entry in the SPT for upage, then one is created. upage
   is then allocated in memory */
void stack_growth(void * upage) {
  
  struct page * new_pg = page_lookup(upage);
  if(!new_pg) {
    // Create the stack page, set its members, and add it to the SPT
    new_pg = malloc(sizeof(struct page));
    ASSERT(new_pg != NULL);
    new_pg->user_vaddr = upage;
    new_pg->writable = true;
    new_pg->thr = thread_current();
    new_pg->pinned = false;
    lock_acquire(&new_pg->thr->spt_lock);
    ASSERT(hash_insert(&thread_current()->supp_page_table, 
                       &new_pg->supp_page_table_elem) == NULL);
    // if(hash_insert(&thread_current()->supp_page_table, 
    //     &new_pg->supp_page_table_elem)) {
    //   free(new_pg);
    //   return;
    //}
    lock_release(&new_pg->thr->spt_lock);
  } 
  uint8_t *kpage = falloc_get_page (PAL_USER, upage);
  if (!install_page(upage, kpage, new_pg->writable)){
    falloc_free_page(upage);
  }
  return;
}
/* End of Matthew and Garrett driving */
