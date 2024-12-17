#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

/* Exit Error Number. */
#define EXIT_ERROR -1

void syscall_init (void);
void sys_exit (int status);
void acquire_filesys_lock (void);
void release_filesys_lock (void);
void relinquish_filesys_lock (void);

#endif /* userprog/syscall.h */
