#include <syscall.h>
#include "../syscall-nr.h"
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include <list.h>
#include "vm/page.h"
#include "userprog/process.h"
#include "userprog/exception.h"

static void syscall_handler (struct intr_frame *);
static bool valid_pointer (const void *);
static void call_cases(uint32_t *, struct intr_frame *);
bool create(const char *, unsigned);
bool remove(const char *);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

void syscall_init(void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_system_lock); // initialize lock
}

static void
syscall_handler(struct intr_frame *f) {
  /* Matthew, Garrett, Vignesh, and Prajit drove here */
  uint32_t *esp = (uint32_t *) f->esp;
  thread_current()->stack_pointer = esp;
  if(valid_pointer(esp) && valid_pointer(esp+1) && valid_pointer(esp+2) 
      && valid_pointer(esp+3)) {
    call_cases(esp, f);
  }
  else
    thread_exit ();
}

static void call_cases(uint32_t *esp, struct intr_frame *f) {

  int call = *(int *)(esp); // call number (see pintos/src/lib/syscall-nr.h)
  /* Case statements to determine what function
     to call. Each case pops arguments from the
     stack and passes them to their respective
     system call */
  if(call == SYS_HALT) {
    halt();
  } else if(call == SYS_EXIT) {
    exit(*(int*)(esp + 1));
  } else if(call == SYS_EXEC) {
    f->eax = exec((char *) *(esp + 1));
  } else if(call == SYS_WAIT) {
    f->eax = wait(*(int*)(esp + 1));
  } else if(call == SYS_CREATE) {
    const char * file = (char *) * (esp+1);
    unsigned size = (unsigned) * (esp+2);
    f->eax = create(file, size);
  } else if(call == SYS_REMOVE) {
    const char * file = (char *) * (esp+1);
    f->eax = remove(file);
  } else if(call == SYS_OPEN) {
    f->eax = open((char *)*(esp + 1));
  } else if(call == SYS_WRITE) {
    int fd = (int *) *(esp + 1);
    const void *buffer = (const void *) *(esp + 2);
    unsigned size = (unsigned) *(esp + 3);
    f->eax = write(fd, buffer, size);
    unpin(buffer, size);
  } else if(call == SYS_READ) {
    int fd = (int *) *(esp + 1);
    const void *buffer = (const void *) *(esp + 2);
    unsigned size = (unsigned) *(esp + 3);
    f->eax = read(fd, buffer, size);
    unpin(buffer, size);    
  } else if(call == SYS_FILESIZE) {
    int fd = *(int *) (esp + 1);
    f->eax = filesize(fd);
  } else if(call == SYS_SEEK) {
    int fd = *(int *) (esp + 1);
    unsigned position = (unsigned) * (esp + 2);
    seek(fd, position);
  } else if(call == SYS_TELL) {
    int fd = *(int *) (esp + 1);
    f->eax = tell(fd);
  } else if(call == SYS_CLOSE) {
    int fd = *(int *) (esp + 1);
    close(fd);
  }
  /*End of Matthew, Garrett, Vignesh, and Prajit driving */
}

/* Prajit and Vignesh drove here */
/* Terminates pintos */
void halt(){
  shutdown_power_off();
}

/* Terminates current user program, returning exit status to kernel */
void exit(int status) {    /* maximum of 128 open files */
  thread_current()->exit_status = status;
  thread_exit();
}
/*End of Prajit and Vignesh driving */

/* Runs executable file whose name is given in cmdline.
   Returns the new process's program id. */
int exec(char *cmdline) {
/* Garrett drove here */
  /* validate cmdline */
  if(cmdline == NULL) {
    return -1;
  }
  if(!valid_pointer(cmdline)) {
    return -1;
  }

  /* allocate space for cmdline */
  char *cmdline_copy = palloc_get_page(0);
  strlcpy(cmdline_copy, cmdline, strlen(cmdline) + 1);
  struct thread *cur = thread_current();
  cur->child_loaded = false;
  cur->child_loaded_successfully = false;
  cur->execd = true;
  int tid = process_execute(cmdline_copy); // execute a new thread
  
  while(!cur->child_loaded) {
    // wait until child has loaded
    sema_down(&cur->waiting_on_child_semaphore);
  }
  if(cur->child_loaded_successfully) {
    return tid;
  } else {
    return -1;
  }
/* End of Garrett driving */
}

/* Waits for a child process pid and retrieves the exit status */
int wait(int pid) {
  /* Matthew drove here */
  int wait_return_value = process_wait(pid);
  return wait_return_value;
  /* End of Matthew driving */
}

/* Create a new file called file with initial size of initial_size bytes */
bool create(const char *file, unsigned initial_size) {
  /* Garrett and Prajit driving */
  /* validate file name */
  if(!valid_pointer(file))
    exit(-1);

  bool b;
  lock_acquire(&file_system_lock);
  b = filesys_create(file, initial_size, false);
  lock_release(&file_system_lock);
  return b;
  /* End of Garrett and Prajit driving */
}

/* Deletes the file called file. Return true if deleted, false otherwise */
bool remove(const char *file) {
  /* Matthew and Garret driving */
  /* validate file */
  if(!valid_pointer(file))
    exit(-1);
  bool b;
  lock_acquire(&file_system_lock);
  b = filesys_remove(file);
  lock_release(&file_system_lock);
  return b;
  /* End of Matthew and Garrett driving */
}

/* Opens the file called file. Return nonnegative integer handle */
int open(const char *file_name) {
  /* Garrett driving */
  /* validate file_name */
  if(!valid_pointer(file_name))
    exit(-1);

  int size = strlen(file_name);
  validate_write_buffer(file_name, size);
  

  lock_acquire(&file_system_lock); // acquire file system lock
  struct file *file = filesys_open(file_name); /* open file using 
                                                  file system call */
  lock_release(&file_system_lock); // release file system lock
  
  /* validate file */
  if(file != NULL) {
    int fd = thread_current()->fd; // get file descriptor
    /* validate fd (maximum of 128 open files) */
    if(fd <= 127) {
      /* make sure thread is not trying to overwrite
         it's executable */
      if(strcmp(thread_current()->name, file_name) == 0)
        file_deny_write(file);

      thread_current()->files[fd] = file; /* index into array using fd and set
                                             return value to this index */
      thread_current()->fd++; // next file descriptor will be unique
      return fd;  
    }
  }
  return -1; // couldn't open file 
  /*End Garrett driving */
}

/* Returns the size of the file open given file descriptor fd */
int filesize(int fd) {
  /* Matthew driving here */
  /* validate fd */
  if(fd < 0 || fd > 127) {
    exit(-1);
  }

  struct file *file = thread_current()->files[fd];
  if(file == NULL)
    return -1;
  return file_length(file);
  /* End of Matthew driving */
}

/* Reads from the open file into buffer. Returns number of bytes read */
int read(int fd, void *buffer, unsigned size) {
  /* Garrett driving here */

  /* validate and pin buffer */
  validate_read_buffer(buffer, size);
  pin(buffer, size);

  /* validate fd */
  if(fd == 0) {
    /* sdtin */
    uint8_t *cbuffer = (uint8_t *) buffer;
    int i;
    for(i = 0; i < size; i++) {
      cbuffer[i] = input_getc();
    }
    return i + 1;
  } else if(fd < 0 ||
            fd == 1 ||
            fd > 127 ||
            thread_current()->files[fd] == NULL) {
    exit(-1); // bad file descriptor
  } else {
    struct file *file = thread_current()->files[fd];
    lock_acquire(&file_system_lock);
    int bytes_read = (int) file_read(file, buffer, size);
    lock_release(&file_system_lock);
    return bytes_read;
  }
  /* End of Garrett driving here */
}

/* Garrett drove here. pins all the pages
   between buffer and buffer + size, thus
   disallowing them from being evicted. If
   any page between buffer and buffer + size
   is not in memory, then it is faulted in.(This
   prevents a page fault from occuring while
   file_read is called) */
void pin(void *buffer, int size) {
  int i;
  char *b = (char *) buffer;
  struct page *p = NULL;
  for(i = 0; i < size; i++) {
    volatile char temp = *b; // fault the page in
    p = page_lookup(pg_round_down(buffer+i));
    p->pinned = true;
    b++;
  }
}

/* unpins the pages in memory, thus allowing
   them to be evicted */
void unpin(void *buffer, int size) {
  int i;
  char * b = (char *) buffer;
  struct page *p = NULL;
  for(i = 0; i < size; i++) {
    p = page_lookup(pg_round_down(b));
    p->pinned = false;
    b++;
  }
}


/* validates all of the address' of buffer. If any
   address between buffer and buffer + size. If any of these
   address' are not writable, then the thread exits with
   -1. */
void validate_read_buffer(void *buffer, int size) {
  int i;
  char * b = (char *) buffer;
  for(i = 0; i < size; i++) {
    if(!valid_pointer(b))
      exit(-1);
    struct page *p = page_lookup(pg_round_down(b));
    if(!p->writable) {
      exit(-1);
    }
    b++;
  }
}

/* validates all of the address' of buffer. */
void validate_write_buffer(void *buffer, int size) {
  if(buffer == NULL) {
    thread_exit();
  }
  int i;
  char * b = (char *) buffer;

  for(i = 0; i < size; i++) {
    if(!valid_pointer(b))
      exit(-1);
    b++;
  }
}
/* End of Garrett driving */

/* Writes from buffer to open file. Return number of bytes actually written */
int write(int fd, const void *buffer, unsigned size) {
  /* Matthew, Prajit, and Garrett driving here */

  /* validate and pin buffer */
  validate_write_buffer(buffer, size);
  pin(buffer, size);

  if(fd <= 0 ||
     fd > 127 ||
     (thread_current()->files[fd] == NULL && fd != 1)) {
    exit(-1); // bad file descriptor
  }

  if(fd == 1){
    /* printing to stdout */
    putbuf((char *) buffer, (size_t) size);
    return size;
  } else {
    struct file *file = thread_current()->files[fd];
    if(fd == 2) {
      return 0; // 2 is reserved for a thread's executable
    }

    lock_acquire(&file_system_lock);
    int bytes_written = (int) file_write(file, buffer, size);
    lock_release(&file_system_lock);
    return bytes_written;
  }
  /* End of Matthew, Prajit, and Garrett driving */
}

/* Change the next byte to be read or written in open file to position */
void seek(int fd, unsigned position) {
  /* Matthew drove here */
  lock_acquire(&file_system_lock);
  struct file *file = thread_current()->files[fd];
  if(file == NULL)
    return -1;
  else {
    file_seek(file, position);
  }
  lock_release(&file_system_lock);
  /* End of Matthew driving */
}

/* Returns the position of the next byte to be read or written in open file */
unsigned tell(int fd) {
  /* Matthew driving here */
  lock_acquire(&file_system_lock);
  struct file *file = thread_current()->files[fd];
  unsigned tell_val;
  if(file == NULL)
    return -1;
  else {
    tell_val = file_tell(file);
  }
  lock_release(&file_system_lock);
  return tell_val;
  /* End of Matthew driving */
}

/* Close file descriptor fd */
void close(int fd) { 
  /* Matthew and Garrett driving here */
  struct file *file = thread_current()->files[fd];
  if(fd == 0 || 1) {
    /* stdin/stdout */
  } else if(file == NULL || fd < 0 || fd > 127) {
    exit(-1);
  } else{

  lock_acquire(&file_system_lock);
  file_close(file);
  /* REMOVE CLOSED FILE FROM THE ARRAY OF FILES */
  thread_current()->files[fd] = NULL;
  lock_release(&file_system_lock);
  }
  /* End of Matthew and Garrett driving */
}

/* Verifies that user provided pointer is valid. 
   If ptr is a valid virtual stack address and it does
   not have an entry in current thread's supplemental
   page table (SPT), then we create an entry for it by 
   growing the stack. If ptr already has an entry in
   the current thread's SPT then we load its corresponding
   page into memory if it has not already done so.*/
static bool valid_pointer (const void *ptr) {
  /* Matthew and Garrett drove here */
  /* Make sure the user give pointer is not null */
  if(ptr == NULL)
    return false;
  
  /* Make sure the user given pointer points to user virtual address 
     space, not kernel */  
  if(!is_user_vaddr(ptr))
    return false;
  
  struct thread *cur = thread_current();
  /* lookup the page in the spt */
  struct page *p = page_lookup(pg_round_down(ptr));
  if(p == NULL) {
    /* create page if there isn't one */
    if(ptr >= (PHYS_BASE - STACK_LIMIT) && ptr >= (cur->stack_pointer - 32)) {
      stack_growth(pg_round_down(ptr));
    } else
        return false;
  } else { 
    if(!p->loc == MAIN_MEMORY) {
      // if the page is not in memory, load the page
      bool success = load_segment(p->user_vaddr);
      if(!success)
        return false;
    }
  }

  return true;
  /* End of Matthew and Garrett driving */
}
