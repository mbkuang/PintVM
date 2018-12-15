#include "frame.h"
#include "threads/palloc.h"
#include "lib/kernel/list.h"
#include "threads/vaddr.h"
#include "userprog/exception.h"

static struct list_elem * clock_hand;
static struct list frame_table;

/* Initialize the frame table */
void frame_init (void) {
	/* Matthew drove here */
	list_init(&frame_table);
	lock_init(&ft_lock);
	clock_hand = malloc(sizeof(struct page));
	ASSERT(clock_hand != NULL);
	/* End of Matthew driving */
}

/* Allocate a new page in memory and add it to the 
   frame table. If upage does not already have an 
   entry in the current threads's SPT then an entry 
   is created and added to the thread's SPT. */
void * falloc_get_page (enum palloc_flags flags, void *upage) {
	/* Matthew and Garrett drove here */
	void * frame = NULL;

	struct page *p = page_lookup(upage);
	if(!p) {
		// If there is not any entry for p in the
		// supplemental page table, then we must 
		// add one
		p = malloc(sizeof(struct page));
		ASSERT(p != NULL);
		p->user_vaddr = pg_round_down(upage);
		p->writable = true;
		p->thr = thread_current();
		p->pinned = false;
		lock_acquire(&p->thr->spt_lock);
		ASSERT(hash_insert(&thread_current()->supp_page_table, 
						   &p->supp_page_table_elem) == NULL);
		lock_release(&p->thr->spt_lock);
	}

	frame = palloc_get_page(flags); // get a page of memory

	if(frame == NULL) {
		frame = evict_page();
	}

	lock_acquire(&ft_lock);
	list_push_back(&frame_table, &p->frame_table_elem);
	p->loc = MAIN_MEMORY;
	lock_release(&ft_lock);
	return frame;
}

/* Remove the given page from the frame table and free
   its page in memory if it has one. */
void falloc_free_page (void *upage) {
	lock_acquire(&ft_lock);
	struct page *p = page_lookup(upage);
	void *kpage = pagedir_get_page(p->thr->pagedir, p->user_vaddr);
	if(kpage != NULL) {
		/* this page is still mapped to memory, we must
		   clear this mapping and free the memory */
		ASSERT(list_remove(&p->frame_table_elem) != NULL);
		pagedir_clear_page(p->thr->pagedir, p->user_vaddr);
		palloc_free_page(kpage);
	}
	lock_release(&ft_lock); 
	/* End of Matthew and Garrett driving */
}

/* Implements the clock eviction policy. Finds a page to be evicted
	based on whether it has been accessed and sends to page to swap/disk. */
void * evict_page() {
	/* Garrett and Matthew drove here */
	bool found = 0;
	struct page *p = NULL;

	while(1) {
		lock_acquire(&ft_lock);
		clock_hand = list_begin(&frame_table);
		while(clock_hand != list_end(&frame_table)) {
			p = list_entry(clock_hand, struct page, frame_table_elem);
			lock_acquire(&p->thr->spt_lock);
			if(!p->pinned) {
				// Check if the page has been accessed in the last loop of
				// the clock hand
				if(!pagedir_is_accessed(p->thr->pagedir, p->user_vaddr)) {
					found = 1; // we found an eviction candidate
					// If the page is modified, it must be written to swap
					if(pagedir_is_dirty(p->thr->pagedir, p->user_vaddr)) {
						p->loc = SWAP;
						ASSERT(block_write_swap(p) != -1);
					} else {
						/* if the page is not modified, we need not write it */
						if(p->user_vaddr >= (PHYS_BASE - STACK_LIMIT) && 
						   p->user_vaddr >= (p->thr->stack_pointer - 32))
							p->loc = STACK;
						else
							p->loc = DISK;
					}
					
					/* save the evictees frame address then remove
					   the evictees memory mapping and remove it from
					   the frame table list. return the saved frame address */
					void *kpage = pagedir_get_page(p->thr->pagedir, 
													p->user_vaddr);
					ASSERT(list_remove(&p->frame_table_elem) != NULL);
					pagedir_clear_page(p->thr->pagedir, p->user_vaddr);
					lock_release(&ft_lock);
					lock_release(&p->thr->spt_lock);
					return kpage;
				}
				pagedir_set_accessed(p->thr->pagedir, p->user_vaddr, 0);
			}
			lock_release(&p->thr->spt_lock);
			clock_hand = list_next(clock_hand);
		}
		lock_release(&ft_lock); /* release the lock if frame are pinned */
	}
	/* End of Garrett and Matthew driving */
}
