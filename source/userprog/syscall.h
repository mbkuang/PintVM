#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
int filesize(int fd);
void validate_write_buffer(void *buffer, int size);
void validate_read_buffer(void *buffer, int size);
void pin(void *buffer, int size);
void unpin(void *buffer, int size);
struct lock file_system_lock; 

#endif /* userprog/syscall.h */
