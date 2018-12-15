#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "lib/kernel/hash.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
static const int MAX_ARGS = 20;
static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmdline) 
{
  /* Matthew, Garrett, Prajit, Vignesh driving here */
  char *cmdline_copy, *file_name, *save_ptr, *cmdline_copy2;
  tid_t tid;

  /* Make a copy of cmdline.
     Otherwise there's a race between the caller and load(). */
  cmdline_copy = palloc_get_page(0);
  cmdline_copy2 = palloc_get_page(0);
  file_name = palloc_get_page(0);

  if (cmdline_copy == NULL || cmdline_copy2 == NULL)
    return TID_ERROR;
  strlcpy (cmdline_copy, cmdline, strlen(cmdline) + 1);
  strlcpy (cmdline_copy2, cmdline, strlen(cmdline) + 1);

  file_name = strtok_r(cmdline_copy, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, cmdline_copy2);
  if (tid == TID_ERROR)
    palloc_free_page (cmdline_copy); 
  return tid;
  /* End of Matthew, Garrett, Prajit, Vignesh driving */
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *cmdline_)
{
  char *cmdline = cmdline_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (cmdline, &if_.eip, &if_.esp);


  /* if the parent thread execd, we need to notify it
     of the load status
  */
  struct thread *cur = thread_current();
  cur->parent_thread->child_loaded = true;
  cur->parent_thread->child_loaded_successfully = success;
  if(cur->parent_thread->execd) {
    // the parent thread called exec on cur
    sema_up(&cur->parent_thread->waiting_on_child_semaphore);
  }

  /* If load failed, quit. */
  palloc_free_page (cmdline);
  if (!success){ 
    thread_exit ();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  /* Garrett and Matthew driving here */
    struct thread *calling_thread = thread_current();
    /* loop through children and see if child_tid is still alive */
    bool child_with_tid_exists = false;
    struct list_elem *e;
    for (e = list_begin(&thread_current()->children_threads); 
         e != list_end(&thread_current()->children_threads);
         e = list_next(e)) {
      
      struct thread *t = list_entry(e, struct thread, children_threads_elem);
      if(t->tid == child_tid){
        calling_thread->waiting_on_tid = child_tid;
        sema_down(&calling_thread->waiting_on_child_semaphore);
        calling_thread->waiting_on_tid = 500; // dummy value       
        child_with_tid_exists = true;
        break; 
      }
    }

    /* loop through terminated children and see if child_tid was reaped */
    for (e = list_begin(&thread_current()->terminated_threads); 
         e != list_end(&thread_current()->terminated_threads);
         e = list_next(e)) {
      
      struct terminated_thread *t = list_entry(e, 
                    struct terminated_thread, terminated_thread_elem);
      if(t->tid == child_tid){
        /* child_tid has already terminated */
        if(t->has_been_waited_on && !child_with_tid_exists) {
          /* child_tid has already been waited on */
          return -1;
        } else {
          t->has_been_waited_on = true;
          return t->exit_status;// found child with matching tid
        }
      }
    }
    /* invalid tid */
    return -1;   
    /* End of Garrett and Matthew driving */    
}

/* Free the current process's resources. */
void
process_exit (void)
{
  /* Garrett drove here */
  struct thread *cur = thread_current ();
  uint32_t *pd;

  if(cur->exit_status == 500) {
    cur->exit_status = -1;
  }
  list_remove(&cur->children_threads_elem); // leaving the nest :)

  struct terminated_thread *t;
  t = palloc_get_page (PAL_ZERO);

  t->exit_status = cur->exit_status;
  t->tid = cur->tid;
  t->has_been_waited_on = false;
  list_push_back(&cur->parent_thread->terminated_threads, 
                 &t->terminated_thread_elem);
  
  int i;
  for(i = 3; i < 128; i++) {
    if(cur->files[i] != NULL) {
      //printf("i %d\n", i);
      file_close(cur->files[i]);
    }
  }

  /* Reclaim thread's resources */

  // free up memory associated with supp_page_table
  hash_destroy(&thread_current()->supp_page_table, spt_action_func);

  if(cur->parent_thread->waiting_on_tid == cur->tid){
    t->has_been_waited_on = true;
    sema_up(&cur->parent_thread->waiting_on_child_semaphore);
  }

  printf("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
  /* End of Garrett driving */
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *cmdline);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool lazy_load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *cmdline, void (**eip) (void), void **esp) 
{
  /* Prajit driving here */
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  char *file_name, *save_ptr, *cmdline_copy;
  file_name = palloc_get_page (0);
  cmdline_copy = palloc_get_page (0);


  strlcpy (cmdline_copy, (char *) cmdline, strlen(cmdline) + 1);
  file_name = strtok_r(cmdline_copy, " ", &save_ptr);

  /* Allocate and activate page directory and SPT */
  t->pagedir = pagedir_create ();
  hash_init(&t->supp_page_table, spt_hash_func, spt_less_func, NULL);
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_acquire(&file_system_lock);
  file = filesys_open(file_name);
  lock_release(&file_system_lock);
  
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* add executable to threads list of open files.
     Just as 0 and 1 are reserved indeces for stdin
     and stdout, 2 is reserved for a threads executable
  */
  thread_current()->files[2] = file;
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!lazy_load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, cmdline))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
  /* End of Prajit driving */
}

/* load() helpers. */


/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Function used for demand paging */
static bool
lazy_load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
  /* Garrett drove here */
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* create spt entry */
      struct page *p = malloc(sizeof(struct page));
      p->file = file;
      p->ofs = ofs;
      p->read_bytes = page_read_bytes;
      p->zero_bytes = page_zero_bytes;
      p->writable = writable;
      p->user_vaddr = upage;
      p->thr = thread_current();
      p->pinned = false;
      p->loc = DISK;
      hash_insert(&thread_current()->supp_page_table, 
                  &p->supp_page_table_elem);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  return true;
  /* End of Garrett driving */
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
bool load_segment(void *upage) 
{
  /* Garrett drove here */
  struct page *p = page_lookup(upage);

  ASSERT(p != NULL);
  ASSERT ((p->read_bytes + p->zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (p->ofs % PGSIZE == 0);

  p->pinned = true;
  if(p->loc == SWAP) {
    /* Get a page of memory. */    
    /* PIN THE FALLOCED PAGE */
    uint8_t *kpage = falloc_get_page (PAL_USER, upage);
    if (!install_page(upage, kpage, p->writable)){
      palloc_free_page(kpage);
      return false; 
    }
    block_read_swap(p, (void *) kpage);
    pagedir_set_dirty(p->thr->pagedir, p->user_vaddr, 1);

  } else if(p->loc == DISK) {
    
    /* Get a page of memory. */
    uint8_t *kpage = falloc_get_page (PAL_USER, upage);

    /* Load this page. */
    lock_acquire(&file_system_lock);
    if (file_read_at(p->file, kpage, p->read_bytes, p->ofs) != 
          (int) p->read_bytes)
      {
        lock_release(&file_system_lock);
        falloc_free_page(p->user_vaddr);
        return false; 
      }

    memset (kpage + p->read_bytes, 0, p->zero_bytes);
    lock_release(&file_system_lock);
    
    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, p->writable)) 
      {
        falloc_free_page(p->user_vaddr);
        return false; 
      }
  }

  p->pinned = false;
  return true;
  /* End of Garrett driving */
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *cmdline) 
{
  /* Matthew and Garrett driving here */
  uint8_t *kpage;
  bool success = false;

  kpage = falloc_get_page (PAL_USER | PAL_ZERO, 
                          pg_round_down(((uint8_t *) PHYS_BASE) - PGSIZE));
  
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = PHYS_BASE;

        char *esp_copy = (char *) *esp; // Used to push arguments onto stack

        /* Should we initialize to NULL? */
        char *token;
        char *save_ptr; 
        char *cmdline_copy;
        /* Holds command line argument addresses */
        char *argv_addresses[MAX_ARGS];
        strlcpy(cmdline_copy, (char *) cmdline, strlen(cmdline) + 1);

        /* Push command line arguments on stack */
        int argc = 0;
        int total_length_of_args = 0; // Cummatively holds length of arguments
        for(token = strtok_r (cmdline_copy, " ", &save_ptr); token != NULL;
            token = strtok_r (NULL, " ", &save_ptr)){
           int token_length = strlen(token) + 1;
           esp_copy -= token_length;
           total_length_of_args += token_length;
           esp_copy = memcpy(esp_copy, token, token_length);
           argv_addresses[argc] = esp_copy;
           argc++;
        }

        /* Should check: if argc > MAX_ARGS then return */

        /* Word alignment (for better access performance) */
        int num_word_align = 4 - total_length_of_args % 4; // 4 byte multiples
        while(num_word_align > 0){
          esp_copy -= sizeof(uint8_t);
          uint8_t word_align = 0;
          esp_copy = memcpy(esp_copy, &word_align, sizeof(uint8_t));
          num_word_align--;
        }

        /* Push Null Terminator on stack */
        int null_terminator = 0;
        esp_copy -= sizeof(int);
        esp_copy = memcpy(esp_copy, &null_terminator, sizeof(int));

        /* Push addresses of command line arguments on stack */
        int i;
        for(i = argc - 1; i >= 0; i--){
          esp_copy -= sizeof(char *);
          esp_copy = memcpy(esp_copy, &argv_addresses[i], sizeof(char *));
        }

        /* Push address of argv on stack */
        char *argv_address = esp_copy;
        esp_copy -= sizeof(char *);
        esp_copy = memcpy(esp_copy, &argv_address, sizeof(char *));
        
        /* Push argc on stack */
        esp_copy -= sizeof(int);
        esp_copy = memcpy(esp_copy, &argc, sizeof(int));
        
        /* Push fake return address on stack */
        int fake_return_address = 0;
        esp_copy -= sizeof(void *);
        esp_copy = memcpy(esp_copy, &fake_return_address, sizeof(void *));

        *esp = esp_copy;
        //hex_dump((int) *esp, *esp, PHYS_BASE - *esp, 1);
      }
      else
        palloc_free_page (kpage);
    }
  return success;
  /* End of Matthew and Garrett driving */
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
