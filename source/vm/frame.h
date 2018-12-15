#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/thread.h"
#include "threads/palloc.h"
#include "vm/page.h"
#include "vm/swap.h"

struct lock ft_lock;

void frame_init (void);
void *falloc_get_page (enum palloc_flags, void *);
void falloc_free_page (void *);
struct page *page_lookup (const void *);
void *evict_page (void);

#endif /* vm/frame.h */
