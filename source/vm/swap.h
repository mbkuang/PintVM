#ifndef VM_SWAP_H
#define VM_SWAP_H

#include "devices/block.h"
#include "threads/thread.h"
#include "vm/page.h"
#include "lib/kernel/bitmap.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

/* Matthew drove here */
struct block * swap_block;
struct bitmap *swap_bitmap;
struct lock swap_lock;
/* End of Matthew driving */

void swap_init (void);
int block_write_swap(struct page *);
int block_read_swap(struct page *, void *);


#endif /* vm/frame.h */
