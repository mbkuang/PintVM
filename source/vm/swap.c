#include "vm/swap.h"

void swap_init (void) {
	/* Matthew and Garrett drove here */
	lock_init(&swap_lock);
	lock_acquire(&swap_lock);
	/* size of block partition is defined per block so
	   we must get the block first */
	if(!(swap_block = block_get_role(BLOCK_SWAP))) {
		PANIC("The block has not been initialized yet!\n");
	}
	/* now we can create a bitmap whose entries will be
	   page aligned with the block */
	int num_entries = block_size(swap_block)/(PGSIZE/BLOCK_SECTOR_SIZE);
	if(!(swap_bitmap = bitmap_create(num_entries))) {
		bitmap_destroy(swap_bitmap);
		PANIC("Could not allocate memory for swap_bitmap!\n");
	}
	bitmap_set_all(swap_bitmap, 0); // a zero entry represents a free page
	lock_release(&swap_lock);
	/* End of Matthew and Garrett driving */
}

/* Garrett drove here */
/* writes a page that is currently in memory
   to the block partition. Returns -1 if */
int block_write_swap (struct page *frame) {
	lock_acquire(&swap_lock);
	if(swap_block == NULL) {
		return -1;
	}
	/* find a free section of the swap block */
	size_t index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
	if(index == BITMAP_ERROR) {
		/* no free pages in swap block */
		// write to file? Im assuming this is coming in project 4
		PANIC("SWAP IS FULL");
	}

	/* starting address of frame data */
	void *k_addr = pagedir_get_page(frame->thr->pagedir, frame->user_vaddr);
	int i;	
	/* loops goes through 8 times because 1 page = 8 sectors*/
	for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++) {
		int sector = index*PGSIZE/BLOCK_SECTOR_SIZE + i; // sector number
		uint8_t *buffer = k_addr + i*BLOCK_SECTOR_SIZE; // starting address
		block_write(swap_block, sector, buffer); // write to sector 
	}
	frame->loc = SWAP; // page is now located in swap
	frame->index = index; // save the swap table index
	lock_release(&swap_lock);
	return 1;
}

/* writes a page that is currently in swap
   to kpage in memory */
int block_read_swap (struct page *page, void *kpage) {
	lock_acquire(&swap_lock);
	if(swap_block == NULL) {
		return -1;
	}
	int sector = page->index*PGSIZE/BLOCK_SECTOR_SIZE; // starting sector

	bitmap_set(swap_bitmap, page->index, 0); // unset swap entry

	int i;	
	/* loops goes through 8 times because 1 page = 8 sectors*/
	for(i = 0; i < PGSIZE/BLOCK_SECTOR_SIZE; i++) {
		block_read(swap_block, sector + i, (uint8_t *) kpage + 
					BLOCK_SECTOR_SIZE*i); // write to sector 
	}
	page->loc = MAIN_MEMORY; // page is now located in memory
	lock_release(&swap_lock);
	return 1;
}
/* End of Garrett driving */
