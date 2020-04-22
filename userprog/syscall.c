#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "user/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/init.h"
#include "lib/string.h"
#include "lib/kernel/stdio.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

//syscall functions

static void halt_s (void);
static void exit_s (int status);
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
			thread_exit();
			f->R.rax=0;
			break;
		case SYS_FORK:
			break;
		case SYS_EXEC:
			break;
		case SYS_WAIT:
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
			seek_s ((const char*)f->R.rdi, (unsigned) f->R.rsi);
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


//syscall support functions
static struct file* fd_get_file(int fd);
//syscall support macros
#define MAX_FILE_NAME 14
#define MAX_OPEN_FILE 64 //temporary
#define EOF (-1)
//syscall support variables 
static char* fd_name_list[MAX_OPEN_FILE]; 
static int fd_current_max=1;
static struct file* fd_file_list[MAX_OPEN_FILE];

static struct file* fd_get_file(int fd){
	if (fd>fd_current_max || fd<=1) return NULL;
	return fd_file_list[fd];
}


static void
halt_s (void){
	power_off();
}


static bool 
create_s (const char *file, unsigned inital_size){
	if (file==NULL) return false;
	if (strlen(file)>MAX_FILE_NAME){
		return false;
	}
	return filesys_create (file, (off_t)inital_size);
}

static bool
remove_s (const char *file){
	if (file==NULL) return false;
	return filesys_remove(file);
}

static int 
open_s (const char *file){
	if (file==NULL) return -1;
	for (int i = 2; i < fd_current_max; i++){
		if (strcmp(fd_name_list[i], file)){
			return i;
		}
		else if (fd_current_max>=MAX_OPEN_FILE){
			return -1;
		}
		else{
			//case that have to open new file;
			struct file* file_struct = filesys_open(file);
			if (file_struct == NULL) return -1;
			file_struct = file_reopen(file_struct);
			fd_current_max++;
			fd_file_list[fd_current_max] = file_struct;
			fd_name_list[fd_current_max] = file;
			return fd_current_max;
		}
	}

}

static int
filesize_s (int fd){
	struct file* file = fd_get_file(fd);
	if (file==NULL) return -1;
	return (off_t) file_length(file);
}

static int
read_s (int fd, void *buffer, unsigned size){
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
	else {
		struct file* file = fd_get_file(fd);
		if (file==NULL) return -1;
		return file_read(file, buffer, size);
	}
}

static int
write_s (int fd, const void *buffer, unsigned size){
	if (size==0) return -1;
	if (fd==1){
		putbuf(buffer, size);
		return size;
	}
	else{
		struct file* file = fd_get_file(fd);
		if (file==NULL) return -1;
		return file_write(file, buffer, size);		
	}
}

static void
seek_s (int fd, unsigned position) {
	struct file* file = fd_get_file(fd);
	file_seek(file, position);
	return;
}

static unsigned
tell_s (int fd){
	struct file* file = fd_get_file(fd);
	return file_tell(file);
}

static void
close_s (int fd){
	struct file* file = fd_get_file(fd);
	file_close(file);
	return;
}