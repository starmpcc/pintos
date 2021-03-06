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
#include "threads/malloc.h"
#include "vm/file.h"
#include "filesys/directory.h"
#include <string.h>
#include "filesys/inode.h"

void syscall_entry (void);
extern struct lock filesys_lock;
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
static int dup2_s(int oldfd, int newfd);
static void* mmap_s (void *addr, size_t length, int writable, int fd, off_t offset);
static void munmap_s (void* addr);

static void is_correct_addr(void* ptr);
static void check_writable_addr(void* ptr);
struct thread_file* get_tf(int fd);

static bool chdir_s (const char* name);
static bool mkdir_s (const char* name);
static bool readdir_s (int fd, char* name);
static bool isdir_s (int fd);
static int inumber_s (int fd);
static int symlink_s (const char* target, const char* linkpath);
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
#define MAX_DIR_DEPTH 32

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
	struct thread* curr = thread_current ();
	curr->saved_sp = f->rsp;

	switch(f->R.rax){
		case SYS_HALT:
			halt_s();
			break;
		case SYS_EXIT:
			f->R.rax = exit_s((int)f->R.rdi);
			break;
		case SYS_FORK:
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
			f->R.rax = (uint64_t) mmap_s ((void*) f->R.rdi, (size_t) f->R.rsi, (int) f->R.rdx, (int) f->R.r10, (off_t) f->R.r8);
			break;
		case SYS_MUNMAP:
			munmap_s ((void*) f->R.rdi);
			break;

	 /* Project 4 only. */
		case SYS_CHDIR:
			f->R.rax = chdir_s((const char*) f->R.rdi);
			break;
		case SYS_MKDIR:
			f->R.rax = mkdir_s((const char*) f->R.rdi);
			break;
		case SYS_READDIR:
			f->R.rax = readdir_s((int) f->R.rdi, (char*) f->R.rsi);
			break;
		case SYS_ISDIR:
			f->R.rax = isdir_s((int) f->R.rdi);
			break;
		case SYS_INUMBER:
			f->R.rax = inumber_s((int) f->R.rdi);
			break;
		case SYS_SYMLINK:
			f->R.rax = symlink_s((const char*) f->R.rdi, (const char*) f->R.rsi);
			break;
	/* Extra for Project 2 */
		case SYS_DUP2:
			f->R.rax = dup2_s ((int)f->R.rdi, (int) f->R.rsi);
			break;
		NOT_REACHED();
	}

}


//syscall support macros
#define MAX_FILE_NAME 14
#define EOF (-1)
//syscall support variables

//syscall support functions
static bool
thread_fd_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED){
	int a_fd = list_entry(a, struct thread_file, elem)->fd;
	int b_fd = list_entry(b, struct thread_file, elem)->fd;
	return a_fd < b_fd;
}

static void
init_stdio(void){
	struct thread* t = thread_current();
	if (!list_empty(&t->open_file)) return;
	struct thread_file* stdin = (struct thread_file *) malloc (sizeof (struct thread_file));
	stdin->file = NULL;
	stdin->fd = 0;
	stdin->dup_tag = -1;
	stdin->dup_cnt = 0;
	stdin->std = 0;
	stdin->dir = NULL;
	struct thread_file* stdout = (struct thread_file *) malloc (sizeof (struct thread_file));
	stdout->file = NULL;
	stdout->fd = 1;
	stdout->dup_tag = -1;
	stdout->dup_cnt = 0;
	stdout->std = 1;
	stdout->dir = NULL;
	list_insert_ordered (&t->open_file, &stdin->elem, thread_fd_less, NULL);
	list_insert_ordered (&t->open_file, &stdout->elem, thread_fd_less, NULL);
	t->open_file_cnt = 2;
}

static bool
check_fd(int fd){
	int fd_max = thread_current()->fd_max;
	if (fd<0 || fd>fd_max) return 0;
	return 1;
}

static struct file*
get_file(int fd){
	struct thread* t = thread_current ();
	if (!list_empty (&t->open_file)){
		for (struct list_elem* i = list_front(&t->open_file); i!=list_end(&t->open_file); i = list_next(i) ){
			struct thread_file* thread_file = list_entry (i, struct thread_file, elem);
			if (fd == thread_file->fd) return thread_file -> file;
		}
	}
	return NULL;
}

struct thread_file*
get_tf(int fd){
	struct thread* t = thread_current ();
	if (!list_empty (&t->open_file)){
		for (struct list_elem* i = list_front(&t->open_file); i!=list_end(&t->open_file); i = list_next(i) ){
			struct thread_file* thread_file = list_entry (i, struct thread_file, elem);
			if (fd == thread_file->fd) return thread_file;
		}
	}
	return NULL;
}

static void
close_file(int fd){
	struct thread* t = thread_current ();
	if (!list_empty (&t->open_file)){
		for (struct list_elem* i = list_front(&t->open_file); i!=list_end(&t->open_file); i = list_next(i) ){
			struct thread_file* thread_file = list_entry (i, struct thread_file, elem);
			if (fd == thread_file->fd){
				if (thread_file -> dup_cnt == 0){
					if (thread_file -> std == -1){
						if (thread_file->dir!= NULL)
							dir_close(thread_file->dir);
						else
							file_close(thread_file -> file);
					}

				}
				else
					thread_file ->dup_cnt--;

				list_remove(&thread_file -> elem);
				free(thread_file);
				return;
			}
		}
	}
}

void
fork_file(struct thread* current, struct thread* parent){
	int cnt =0;
	ASSERT(list_empty (&current->open_file));
	if (!list_empty (&parent->open_file)){
		for (struct list_elem* i = list_front(&parent->open_file); i!=list_end(&parent->open_file); i = list_next(i) ){
			struct thread_file* parent_tf = list_entry (i, struct thread_file, elem);
			struct thread_file* current_tf = (struct thread_file*) malloc (sizeof (struct thread_file));
			ASSERT(parent_tf!=NULL);
			current_tf -> fd = parent_tf -> fd;
			if (parent_tf -> file != NULL)
				current_tf -> file = file_duplicate (parent_tf -> file);
			else
				current_tf->file = NULL;
			current_tf->dup_tag = parent_tf ->dup_tag;

			current_tf->dup_cnt = parent_tf ->dup_cnt;
			current_tf->std = parent_tf->std;
			current_tf->dir = parent_tf->dir;

			list_insert_ordered(&current ->open_file, &current_tf ->elem, thread_fd_less, NULL);
			cnt++;
			if (cnt>=128) break;
		}
		current->fd_max = parent->fd_max;
		current ->open_file_cnt = parent -> open_file_cnt;
	}
}

void
close_all(struct list* l){
	if (list_empty (l)) return;
	while (!list_empty (l))
	{
		struct list_elem *e = list_pop_front (l);
		struct thread_file* tf = list_entry (e, struct thread_file, elem);
		if (tf -> dup_cnt == 0){
			if (tf -> std == -1)
				file_close(tf -> file);
		}
		else
			tf ->dup_cnt--;

		list_remove(&tf -> elem);
		free(tf);

	}
	ASSERT(list_empty(l));
}

static void
is_correct_addr(void* ptr){
	if (ptr == NULL) exit_s(-1);
	if (!is_user_vaddr(ptr)) exit_s(-1);
	uint64_t *pte = pml4e_walk(thread_current()->pml4, (const uint64_t) ptr, 0);
	if (pte == NULL) exit_s(-1);
	struct page *page = spt_find_page (&thread_current() -> spt, ptr);
	if (page == NULL) exit_s(-1);
}

static void
check_writable_addr(void* ptr){
	struct page *page = spt_find_page (&thread_current() -> spt, ptr);
	if (page == NULL || !page->writable) exit_s(-1);
}


static int
get_fd(int fd){
	struct thread* t = thread_current ();
	if (!list_empty (&t->open_file)){
		for (struct list_elem* i = list_front(&t->open_file); i!=list_end(&t->open_file); i = list_next(i) ){
			struct thread_file* thread_file = list_entry (i, struct thread_file, elem);
			if (thread_file->fd == fd){
				if (thread_file -> dup_tag != -1) return thread_file -> dup_tag;
				else return fd;
			}
		}
	}
	return fd;
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

static bool tmp_sym_included(struct dir* dir, char* name){
	if (list_empty(&tmp_sym_list)) return 0;
	for (struct list_elem* i = list_front(&tmp_sym_list); i!=list_end(&tmp_sym_list); i = list_next(i) ){
		struct tmp_sym* ts = list_entry(i, struct tmp_sym, elem);
		bool success = !strcmp(ts->target_name, name);
		success &= (dir_get_inode(dir) == dir_get_inode(ts->target_parent));
		if (success) return 1;
	}
	return 0;
}

static void
tmp_sym_create(struct dir* dir, char* name, struct file* file){
	struct thread* t = thread_current();
	for (struct list_elem* i = list_front(&tmp_sym_list); i!=list_end(&tmp_sym_list); i = list_next(i) ){
		struct tmp_sym* ts = list_entry(i, struct tmp_sym, elem);
		bool success = !strcmp(ts->target_name, name);
		success &= (dir_get_inode(dir) == dir_get_inode(ts->target_parent));
		if (success){
			struct dir* old_dir = t->current_dir;
			t->current_dir = dir_reopen(ts-> link_parent);
			lock_acquire(&filesys_lock);
			filesys_remove(ts->link_name);
			lock_release(&filesys_lock);
			t->current_dir = old_dir;
			disk_sector_t inum = inode_get_inumber(file_get_inode(file));
			dir_add(ts->link_parent, ts->link_name, inum);
		}
	}
}

static bool 
create_s (const char *file, unsigned inital_size){
	is_correct_addr((void*) file);

	struct thread* t= thread_current();
	struct dir* dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();
	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,file,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			if (dir_array[j]==NULL) return 0;
			if (tmp_sym_included(dir, dir_array[j])){
				struct dir* old_dir = t->current_dir;
				t->current_dir = dir_reopen(dir);
				lock_acquire(&filesys_lock);
				filesys_create(dir_array[j], (off_t) inital_size);
				lock_release(&filesys_lock);
				t->current_dir = dir_reopen(dir);
				lock_acquire(&filesys_lock);
				struct file* target = filesys_open(dir_array[j]);
				lock_release(&filesys_lock);
				t->current_dir = old_dir;
				tmp_sym_create(dir, dir_array[j], target);
				return 1;
			}
			if (!dir_lookup(dir, ".", &inode)) return 0;
			dir_lookup(dir, dir_array[j], &inode);
			if (inode!=NULL) return 0;
			if (strlen(dir_array[j])>MAX_FILE_NAME) return 0;
			struct dir* old_dir = t->current_dir;
			t->current_dir = dir_reopen(dir);
			lock_acquire(&filesys_lock);
			filesys_create(dir_array[j], (off_t) inital_size);
			lock_release(&filesys_lock);
			t->current_dir = old_dir;
			free(tmp);
			return 1;
		}
		
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return 0;
	}
	return 0;
}


static bool
remove_s (const char *file){
	is_correct_addr((void*) file);

	struct thread* t= thread_current();
	struct dir* dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();
	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,file,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			if (dir_array[j]==NULL) return 0;

			dir_lookup(dir, dir_array[j], &inode);
			if (inode==NULL){
				//try to delete itself
				if (dir_lookup(pdir(dir), dir_array[j],&inode)){
					struct dir* target = dir_open(inode);
					if (dir_is_elem(target)==1){
						return 0;
					}
					dir_remove(target, ".");
					dir_remove(target, "..");
					dir_remove(pdir(dir), dir_array[j]);
					//parent delete?
					free(tmp);
					return 1;
				}
				else {
					dir_close(pdir(dir));
					return 0;
				}
			} 
			if (is_link(dir, dir_array[j])){
				dir_remove(dir ,dir_array[j]);
				free (tmp);
				return 1;
			}
			if (inode_type(inode) == DIR_INODE){
				struct dir* target = dir_open(inode);
				if (dir_is_elem(target)==1){
					return 0;
				}
				dir_remove(target, ".");
				dir_remove(target, "..");
				dir_remove(dir, dir_array[j]);
				free(tmp);
				return 1;	
			}
			else{
				struct dir* old_dir = t->current_dir;
				t->current_dir = dir_reopen(dir);
				lock_acquire(&filesys_lock);
				filesys_remove(dir_array[j]);
				lock_release(&filesys_lock);
				t->current_dir = old_dir;
				free(tmp);
				return 1;
			}

		}
		
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return 0;
	}
	return 0;
}

static int 
open_s (const char *file){
	init_stdio();
	is_correct_addr((void*) file);
	struct thread* t= thread_current();
	if (t->open_file_cnt >128) return -1;
	t->open_file_cnt++;
	int fd=++t->fd_max;

	if (strcmp(file, "/")==0){
		struct thread_file* tf = (struct thread_file *) malloc(sizeof(struct thread_file));
		tf->fd = fd;
		tf->file = NULL;
		tf->dir = dir_open_root();
		tf -> dup_tag = -1;
		tf -> dup_cnt = 0;
		tf -> std = -1;
		list_insert_ordered(&thread_current () -> open_file, &tf->elem, thread_fd_less, NULL);
		return fd;
	}

	struct dir* dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();

	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,file,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	if (dir_array[0]== NULL) return -1;
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			dir_lookup(dir, dir_array[j], &inode);
			if (inode==NULL) return -1;
			if (inode_type(inode)==DIR_INODE){
				dir = dir_open(inode);
				if (dir == NULL) return -1;
				struct thread_file* tf = (struct thread_file *) malloc(sizeof(struct thread_file));
				tf->fd = fd;
				tf->file = NULL;
				tf->dir = dir;
				tf -> dup_tag = -1;
				tf -> dup_cnt = 0;
				tf -> std = -1;
				list_insert_ordered(&thread_current () -> open_file, &tf->elem, thread_fd_less, NULL);
				free(tmp);
				return fd;
			}
			else{
				struct dir* old_dir = t->current_dir;
				t->current_dir = dir_reopen(dir);
				lock_acquire(&filesys_lock);
				struct file* file_struct = filesys_open(dir_array[j]);
				lock_release(&filesys_lock);
				t->current_dir = old_dir;
				if (file_struct == NULL) return -1;
				struct thread_file* tf = (struct thread_file *) malloc(sizeof(struct thread_file));
				tf->fd = fd;
				tf->file = file_struct;
				tf -> dup_tag = -1;
				tf -> dup_cnt = 0;
				tf -> std = -1;
				tf -> dir = NULL;
				list_insert_ordered(&thread_current () -> open_file, &tf->elem, thread_fd_less, NULL);
				free(tmp);
				return fd;
			}
		}
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return -1;
	}

}

static int
filesize_s (int fd){
	if (!check_fd(fd)) return -1;
	fd = get_fd (fd);
	struct file* file = get_file (fd);
	if (file == NULL) return -1;
	return file_length(file);
}

static int
read_s (int fd, void *buffer, unsigned size){
	init_stdio();
	if (!check_fd(fd)) return -1;
	struct thread_file* tf = get_tf(fd);
	if (tf ->std == 0){
		char tmp[size];
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
	else if (tf ->std == 1) return -1;
	else {
		is_correct_addr(buffer);
		check_writable_addr(buffer);
		struct file* file = get_file (fd);
		if (file == NULL) return -1;
		return file_read(file, buffer, size);
	}
}

static int
write_s (int fd, const void *buffer, unsigned size){
	init_stdio();
	if (!check_fd(fd)) return -1;
	if (size==0) return 0;
	struct thread_file* tf = get_tf (fd);
	if (tf->std == 0) return -1;
	else if (tf ->std == 1){
		putbuf(buffer, size);
		return size;
	}
	else if (tf->dir!= NULL) return -1;
	else{
		is_correct_addr((void*) buffer);
		struct file* file = get_file (fd);
		if (file == NULL) return -1;
		return file_write(file, buffer, size);		
	}
}

static void
seek_s (int fd, unsigned position) {
	fd = get_fd (fd);
	struct file* file = get_file (fd);
	if (file==NULL) return;
	file_seek(file, position);
	return;
}

static unsigned
tell_s (int fd){
	fd = get_fd (fd);
	struct file* file = get_file (fd);
	if (file==NULL) return 0;
	return file_tell(file);
}

static void
close_s (int fd){
	init_stdio();
	if (!check_fd(fd)) return;
	struct thread_file* tf = get_tf (fd);
	if (tf == NULL) return;
	thread_current() -> open_file_cnt--;

	close_file(fd);

}

static int
dup2_s (int oldfd, int newfd){
	init_stdio();
	if (!check_fd(oldfd)) return -1;
	if (oldfd == newfd) return newfd;
	struct thread* t = thread_current();
	struct thread_file* oldtf = get_tf (oldfd);
	if (oldtf == NULL) return -1;
	struct file* file = oldtf->file;
	if (newfd> t->fd_max){
		t->fd_max = newfd;
	}
	if (get_tf(newfd)!=NULL) close_file(newfd);

	struct thread_file* tf = (struct thread_file *) malloc(sizeof(struct thread_file));
	tf->fd = newfd;
	tf->dup_tag = oldfd;
	tf -> dup_cnt = ++oldtf->dup_cnt;
	tf -> std = oldtf-> std;
	if (oldtf->std == 0 || oldtf->std == 1){
		tf->file = NULL;
	}
	else {
		tf->file = file;
	}

	//is newfd already existed, have to remove it first.

	list_insert_ordered(&t->open_file, &tf->elem, thread_fd_less, NULL);
	return newfd;
}

static void*
mmap_s (void *addr, size_t length, int writable, int fd, off_t offset){
	//Handle all parameter error and pass it to do_mmap
	if (addr == 0 || (!is_user_vaddr(addr))) return NULL;
	if ((uint64_t)addr % PGSIZE != 0) return NULL;
	if (offset % PGSIZE != 0) return NULL;
	if ((uint64_t)addr + length == 0) return NULL;
	if (!is_user_vaddr((uint64_t)addr + length)) return NULL;
	for (uint64_t i = (uint64_t) addr; i < (uint64_t) addr + length; i += PGSIZE){
		if (spt_find_page (&thread_current() -> spt, (void*) i)!=NULL) return NULL;
	}
	struct thread_file* tf = get_tf (fd);
	if (tf == NULL) return NULL;
	if (tf->std == 0 || tf->std == 1) return NULL;
	if (length == 0) return NULL;
	struct file* file = tf->file;
	return do_mmap(addr, length, writable, file, offset);
}

static void
munmap_s (void* addr){
	do_munmap(addr);
}

static bool
chdir_s (const char* name){
	is_correct_addr(name);
	if (*name==NULL) return 0;
	struct thread* t= thread_current();
	struct dir* dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();
	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,name,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			dir_lookup(dir, dir_array[j], &inode);
			dir_close(dir);
			dir = dir_open(inode);
			if (dir==NULL) return 0;
			t->current_dir = dir;
			free(tmp);
			return 1;
		}
		
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return 0;
	}
	return 0;
}

static bool
mkdir_s (const char* name){
	is_correct_addr(name);
	if (*name==NULL) return 0;
	struct thread* t= thread_current();
	struct dir* dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();
	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,name,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			dir_lookup(dir, dir_array[j], &inode);
			if (inode!=NULL) return 0;
			disk_sector_t inode_sector = 0;
			thread_current()->pdir = dir;
			bool success = (dir != NULL
					&& fat_allocate (1, &inode_sector)
					&& dir_create (inode_sector, 16)  ///temporal number
					&& dir_add (dir, dir_array[j], inode_sector));
			if (!success && inode_sector != 0){
				fat_remove_chain (inode_sector, 0);
				dir_remove(dir, dir_array[j]);
			}
			free(tmp);
			return success;
		}
		
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return 0;
	}
	return 0;
}
static bool
readdir_s (int fd, char* name){
	struct thread_file* tf = get_tf (fd);
	return dir_readdir(tf->dir, name);
}

static bool
isdir_s (int fd){
	struct thread_file* tf = get_tf(fd);
	if (tf->dir!=NULL) return true;
}

static int
inumber_s (int fd){
	struct thread_file* tf = get_tf(fd);
	if(tf->dir==NULL){
		return inode_get_inumber(file_get_inode(tf->file));
	}
	else{
		struct dir* dir = tf->dir;
		return inode_get_inumber(dir_get_inode(dir));
	}

}

static struct tmp_sym* find_link_root (struct dir* target_dir, char* target_name){
	if (list_empty(&tmp_sym_list)) return NULL;
	for (struct list_elem* i = list_front(&tmp_sym_list); i!=list_end(&tmp_sym_list); i = list_next(i) ){
		struct tmp_sym* ts = list_entry(i, struct tmp_sym, elem);
		bool success = !strcmp((char*)ts->link_name, target_name);
		success &= (dir_get_inode(target_dir) == dir_get_inode(ts->link_parent));
		if (success){
			struct tmp_sym* new_ts = malloc (sizeof (struct tmp_sym));
			new_ts->target_parent = ts->target_parent;
			strlcpy(new_ts->target_name, ts->target_name,15);
			return new_ts;
		}
	}
	return NULL;

}

static struct inode*
get_inode_of_target(const char* target, struct dir* link_parent, char* link_name){
	is_correct_addr((void*) target);
	struct thread* t= thread_current();
	if (strcmp(target, "/")==0){
		return -1;
	}
	struct dir* dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();

	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,target,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	if (dir_array[0]== NULL) return NULL;
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			dir_lookup(dir, dir_array[j], &inode);
			if (inode==NULL){
				//add to tmp_sym_list;
				struct tmp_sym* ts = malloc(sizeof(struct tmp_sym));
				strlcpy(ts->target_name, dir_array[j], 15);
				ts->target_parent = dir;
				ts->link_parent = link_parent;
				strlcpy(ts->link_name, link_name, 15);
				list_push_back(&tmp_sym_list, &ts->elem);
				struct dir* old_dir = t->current_dir;
				t->current_dir = dir_reopen(link_parent);
				lock_acquire(&filesys_lock);
				filesys_create(link_name, 0);
				lock_release(&filesys_lock);
				t->current_dir = old_dir;
				set_link(link_parent, link_name);
				return (struct inode*) UINT64_MAX;
			}
			if (is_link(dir, dir_array[j])){
				struct tmp_sym* ts = find_link_root(dir, dir_array[j]);
				ts->link_parent = link_parent;
				strlcpy(ts->link_name, link_name, 15);
				list_push_back(&tmp_sym_list, &ts->elem);
				struct dir* old_dir = t->current_dir;
				t->current_dir = dir_reopen(link_parent);
				lock_acquire(&filesys_lock);
				filesys_create(link_name, 0);
				lock_release(&filesys_lock);
				t->current_dir = old_dir;
				set_link(link_parent, link_name);
				return (struct inode*) UINT64_MAX;
			}
			if (inode_type(inode)==DIR_INODE){
				dir = dir_open(inode);
				if (dir == NULL) return -1;
				free(tmp);
				return inode;
			}
			else{
				struct dir* old_dir = t->current_dir;
				t->current_dir = dir_reopen(dir);
				lock_acquire(&filesys_lock);
				struct file* file = filesys_open(dir_array[j]);
				lock_release(&filesys_lock);
				t->current_dir = old_dir;
				struct tmp_sym* ts = malloc(sizeof(struct tmp_sym));
				strlcpy(ts->target_name, dir_array[j], 15);
				ts->target_parent = dir;
				ts->link_parent = link_parent;
				strlcpy(ts->link_name, link_name, 15);
				list_push_back(&tmp_sym_list, &ts->elem);

				free(tmp);
				return file_get_inode(file);
			}
		}
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return -1;
	}

}

static int 
symlink_s (const char* target, const char* linkpath){
	
	is_correct_addr((void*) target);
	is_correct_addr((void*) linkpath);
	struct thread* t= thread_current();

	if (strcmp(target, "/")==0){
		return -1;
	}

	struct dir* dir = t->current_dir;
	struct dir* old_dir = t->current_dir;
	if (dir == NULL)
		dir = dir_open_root();

	char* dir_array[MAX_DIR_DEPTH]={};
	char* tmp = malloc(sizeof(char)*512);
	strlcpy(tmp,linkpath,512);
	//directory support
	char* buf;
	char* cut;
	struct inode* inode = NULL;
	int i = 0;
	cut = strtok_r((char*)tmp, "/", &buf);
	while (cut!=NULL){
		dir_array[i] = cut;
		i++;
		cut = strtok_r(NULL, "/", &buf);
	}
	if (dir_array[0]== NULL) return -1;
	for (int j=0;j<=i;j++){
		if (dir_array[j+1]==NULL){
			dir_lookup(dir, dir_array[j], &inode);
			if (inode!=NULL) return -1;
			struct inode* inode = get_inode_of_target(target, dir, dir_array[j]);
			if (inode==NULL) return -1;
			if (inode == (struct inode*) UINT64_MAX){
				free(tmp);
				return 0;
			}
			dir_add(dir, dir_array[j], inode_get_inumber(inode));
			set_link(dir, dir_array[j]);
			free(tmp);
			return 0;
		}
		dir_lookup(dir, dir_array[j], &inode);
		dir_close(dir);
		dir = dir_open(inode);
		if (dir==NULL) return -1;
	}

}
