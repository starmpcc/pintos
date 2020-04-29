#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "user/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "lib/string.h"
#include "lib/kernel/stdio.h"
#include "lib/kernel/list.h"
#include "devices/input.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
void syscall_entry (void);

//syscall functions

static void halt_s (void);
static int exit_s (int status);
static int exec_s (char *input);
static bool create_s (const char*file, unsigned inital_size);
static bool remove_s (const char *file);
static int open_s (const char* file);
static int filesize_s (int fd);
static int read_s (int fd, void *buffer, unsigned size);
static int write_s (int fd, const void *buffer, unsigned size);
static void seek_s (int fd, unsigned position);
static unsigned tell_s (int fd);
static void close_s (int fd);

static void is_correct_addr(void* ptr);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f) {
	// TODO: Your implementation goes here.
	switch(f->R.rax){
		case SYS_HALT:
			halt_s();
			break;
		case SYS_EXIT:
			// TODO(chanil): setting exitcode to current thread?
			f->R.rax = exit_s((int)f->R.rdi);
			break;
		case SYS_FORK:
			// printf("forking thread name %s\n", thread_current ()->name); // > "fork-once"
			// NOTE(chanil): I don't understand why f instead of &thread_current ()->tf
			//f->R.rax = process_fork ((const char*)f->R.rdi, &thread_current ()->tf);
			is_correct_addr((void*)f->R.rdi);
			f->R.rax = process_fork ((const char*)f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = exec_s ((char *)f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = process_wait ((tid_t)f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = create_s ((const char*)f->R.rdi, (unsigned) f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove_s ((const char*)f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open_s ((const char*) f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize_s ((int) f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read_s ((int) f->R.rdi, (void*) f->R.rsi, (unsigned int) f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write_s ((int) f->R.rdi, (void*) f->R.rsi, (unsigned int) f->R.rdx);
			break;
		case SYS_SEEK:
			seek_s ((int)f->R.rdi, (unsigned) f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell_s ((int) f->R.rdi);
			break;
		case SYS_CLOSE:
			close_s ((int) f->R.rdi);
			break;
	/* Project 3 and optionally project 4. */
		case SYS_MMAP:
			break;
		case SYS_MUNMAP:
			break;

	 /* Project 4 only. */
		case SYS_CHDIR:
			break;
		case SYS_MKDIR:
			break;
		case SYS_READDIR:
			break;
		case SYS_ISDIR:
			break;
		case SYS_INUMBER:
			break;
	/* Extra for Project 2 */
		case SYS_DUP2:
			break;
		NOT_REACHED();
	}

}


//syscall support macros
#define MAX_FILE_NAME 14
#define MAX_OPEN_FILE 64 //temporary
#define EOF (-1)
//syscall support variables
static struct inode* opened_file_inode[MAX_OPEN_FILE];
static int opened_file_cnt[MAX_OPEN_FILE] = {0,};
int opened_file_number=0;
//syscall support functions
static void
open_global(struct file* file){
	int flag = 0;
	for (int i = 1; i  <=opened_file_number;i++){
		if (file->inode == opened_file_inode[i]){
			flag=1;
			break;
		}
	}
	if (flag==0){
		opened_file_number++;
		opened_file_inode[opened_file_number-1] = file->inode;
		opened_file_cnt[opened_file_number-1]++;
	}
}

static void
close_global(struct file* file){
	for (int i = 1; i  <=opened_file_number;i++){
		if (file->inode == opened_file_inode[i]){
			opened_file_cnt[i]--;
			if (opened_file_cnt[i]==0){
				file_close(file);
			}
			break;
		}
	}
}


static bool
check_fd(int fd){
	int fd_max = thread_current() ->fd_max;
	if (fd<0 || fd> MAX_OPEN_FILE || fd>fd_max) return 0;
	return 1;
}

void
fork_file(struct thread* current, struct thread* parent){
	for (int i=1; i<=parent->fd_max;i++){
		if (parent->open_file[i]!=NULL) {
			current->open_file[i] = file_duplicate(parent->open_file[i]);
			open_global(current->open_file[i]);
		}
	}
	current->fd_max = parent->fd_max;
}

static void
is_correct_addr(void* ptr){
	if (ptr == NULL) exit_s(-1);
	if (!is_user_vaddr(ptr)) exit_s(-1);
	if (pml4e_walk(thread_current()->pml4, (const uint64_t) ptr, 0)==NULL) exit_s(-1);
}

static void
halt_s (void){
	power_off();
}

static int
exit_s (int status){
	thread_current ()->exitcode = status;
	thread_exit();
	return status;
}

static int
exec_s (char *input) {
	is_correct_addr((void*) input);
	/* Make a copy of input from user memory to kernel page. */
	char *in_copy;
	in_copy = palloc_get_page (0);
	if (in_copy == NULL)
		return TID_ERROR;
	strlcpy (in_copy, input, PGSIZE);

	return process_exec(in_copy);
}

static bool 
create_s (const char *file, unsigned inital_size){
	is_correct_addr((void*) file);
	if (strlen(file)>MAX_FILE_NAME) return false;
	//need to check file vaildation
	return filesys_create (file, (off_t)inital_size);
}

static bool
remove_s (const char *file){
	is_correct_addr((void*) file);
	if (!is_user_vaddr(file)) exit_s(-1);
	return filesys_remove(file);
}

static int 
open_s (const char *file){
	is_correct_addr((void*) file);
	int fd=++thread_current()->fd_max;
	ASSERT(fd<32);
	struct file* file_struct = filesys_open(file);
	if (file_struct == NULL) return -1;
	thread_current()->open_file[fd] = file_struct;
	open_global(file_struct);
	return fd;
}

static int
filesize_s (int fd){
	if (!check_fd(fd)) return -1;
	struct file* file = thread_current()->open_file[fd];
	if (file == NULL) return -1;
	return file_length(file);
}

static int
read_s (int fd, void *buffer, unsigned size){
	if (!check_fd(fd)) return -1;
	char tmp[size];
	if (fd==0){
		for (int i=1;i<= (int) size;i++){
			tmp[i] = (char) input_getc();
			if (tmp[i]==EOF){
				strlcpy(buffer, tmp, i);
				return i;
			}
		}
		strlcpy(buffer, tmp, size);
		return size;
	}
	else if (fd == 1) return -1;
	else {
		is_correct_addr((void*) buffer);
		struct file* file = thread_current()->open_file[fd];
		if (file == NULL) return -1;
		return file_read(file, buffer, size);
	}
}

static int
write_s (int fd, const void *buffer, unsigned size){
	if (!check_fd(fd)) return -1;
	if (size==0) return 0;
	if (fd==1){
		putbuf(buffer, size);
		return size;
	}
	else{
		is_correct_addr((void*) buffer);
		struct file* file = thread_current() ->open_file[fd];
		if (file == NULL) return -1;
		return file_write(file, buffer, size);		
	}
}

static void
seek_s (int fd, unsigned position) {
	struct file* file = thread_current() ->open_file[fd];
	file_seek(file, position);
	return;
}

static unsigned
tell_s (int fd){
	struct file* file = thread_current() ->open_file[fd];
	return file_tell(file);
}

static void
close_s (int fd){
	if (!check_fd(fd)) return;
	struct file* file = thread_current() ->open_file[fd];
	if (file==NULL) return ;
	close_global(file);
	thread_current()->open_file[fd] = NULL;
}
