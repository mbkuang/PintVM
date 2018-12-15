#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/palloc.h"

/* Matthew drove here */
enum location {
	SWAP = 001,
	MAIN_MEMORY = 002,
	DISK = 003,
	STACK = 004
};
/* End of Matthew driving */

/* Garrett and Prajit drove here */
struct page {
	bool pinned;	// Used so kernel can prevent page faults while it
					// holds resources
	int index;		// Index to indicate swap sector
	struct hash_elem supp_page_table_elem; // Represents the page in the SPT
	struct list_elem frame_table_elem;	//  Represents the page in the FT
	void *user_vaddr;	// The user virtual address
	struct file *file;	// File that the page was read from
	int ofs;	// Offset in file
	uint32_t read_bytes; // bytes to read in file
	uint32_t zero_bytes; // trailing zero bytes in file
	bool writable; // is this page writable?
	enum location loc; // location of page
	struct thread *thr; // thread whose pagedir stores page (user_vaddr)
};
/* End of Garrett and Prajit driving */

void page_init (void);
unsigned spt_hash_func (const struct hash_elem *, void * aux);
bool spt_less_func (const struct hash_elem *,
                             const struct hash_elem *,
                             void * UNUSED);

void spt_action_func (struct hash_elem *, void *);
void stack_growth (void *);

#endif /* vm/page.h */
