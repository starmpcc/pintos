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
void syscall_entry (void);
void syscall_handler (struct intr_frame *);

//syscall functions

static void halt_s (void);
static int exit_s (int status);
static pid_t fork_s (const char *thread_name);
static int exec_s (const char *cmd_line);
static int wait_s (pid_t pid);
static bool create_s (const char*file, unsigned inital_size);
static bool remove_s (const char *file);
static int open_s (const char* file);
static int filesize_s (int fd);
static int read_s (int fd, void *buffer, unsigned size);
static int write_s (int fd, const void *buffer, unsigned size);
static void seek_s (int fd, unsigned position);
static unsigned tell_s (int fd);
static void close_s (int fd);

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
			f->R.rax = process_fork ((const char*)f->R.rdi, f);
			break;
		case SYS_EXEC:
			f->R.rax = process_exec ((void *)f->R.rdi);
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
	int flag = 0;
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

static bool 
create_s (const char *file, unsigned inital_size){
	if (!is_user_vaddr(file)) exit_s(-1);
	if (strlen(file)>MAX_FILE_NAME) return false;
	//need to check file vaildation
	return filesys_create (file, (off_t)inital_size);
}

static bool
remove_s (const char *file){
	if (!is_user_vaddr(file)) exit_s(-1);
	return filesys_remove(file);
}

static int 
open_s (const char *file){
	if (!is_user_vaddr(file)) exit_s(-1);
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
	if (!is_user_vaddr(buffer)) exit_s(-1);
	char tmp[size];
	if (fd==0){
		for (int i=1;i<=size;i++){
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
		struct file* file = thread_current()->open_file[fd];
		if (file == NULL) return -1;
		return file_read(file, buffer, size);
	}
}

static int
write_s (int fd, const void *buffer, unsigned size){
	if (!check_fd(fd)) return -1;
	if (!is_user_vaddr(buffer)) exit_s(-1);
	if (size==0) return 0;
	if (fd==1){
		putbuf(buffer, size);
		return size;
	}
	else{
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
	if (!check_fd(fd)) return -1;
	struct file* file = thread_current() ->open_file[fd];
	if (file==NULL) return ;
	close_global(file);
	thread_current()->open_file[fd] = NULL;
}
