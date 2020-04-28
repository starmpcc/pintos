#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "threads/thread.h"

void syscall_init (void);
void syscall_handler (struct intr_frame *);
void fork_file(struct thread* current, struct thread* parent);

#endif /* userprog/syscall.h */
