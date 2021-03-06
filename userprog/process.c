#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "intrinsic.h"
#include "userprog/syscall.h"
#ifdef VM
#include "vm/vm.h"
#endif

/* Used to synchronize shared state children_info_lock */
struct lock children_info_lock;

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *);
static void __do_fork (void *);

struct lock filesys_lock;
/* General process initializer for initd and other process. */
static void
process_init (struct thread *parent) {
	struct thread *curr = thread_current ();
	if (parent != NULL)
	{
		curr->parent = parent;

		// Create new child_info in shared state children_info
		lock_acquire (&children_info_lock);
		struct child_info *cinfo = new_child_info ();
		cinfo->tid = curr->tid;
		cinfo->parent_tid = parent->tid;
		lock_release (&children_info_lock);
	}
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	strlcpy (fn_copy, file_name, PGSIZE);

	/* Create a new thread to execute FILE_NAME. */
	struct fork_args args;
	args.parent = thread_current ();
	args.additional = fn_copy;
	sema_init (&args.return_sema, 0);

	char* cut_name;
	cut_name = strtok_r((char *) file_name, " ", &cut_name);
	tid = thread_create (cut_name, PRI_DEFAULT, initd, &args);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	else
		sema_down (&args.return_sema);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *aux) {
	struct fork_args *args = (struct fork_args *) aux;
	struct thread *parent = args->parent;
	void *f_name = args->additional;
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif

	process_init (parent);
	sema_up (&args->return_sema);

	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
tid_t
process_fork (const char *name, struct intr_frame *if_) {
	/* Clone current thread to new thread.*/
	struct fork_args args;
	args.parent = thread_current ();
	args.additional = if_;
	sema_init (&args.return_sema, 0);
	tid_t child_tid = thread_create (name,
			PRI_DEFAULT, __do_fork, &args);
	if (child_tid != TID_ERROR)
		sema_down (&args.return_sema);
	return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();
	struct thread *parent = (struct thread *) aux;
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. If the parent_page is kernel page, then return immediately. */
	if (is_kernel_vaddr (va))
		return true;

	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va);

	/* 3. Allocate new PAL_USER page for the child and set result to
	 *    NEWPAGE. */
	newpage = palloc_get_page (PAL_USER);

	/* 4. Duplicate parent's page to the new page and
	 *    check whether parent's page is writable or not (set WRITABLE
	 *    according to the result). */
	memcpy (newpage, parent_page, PGSIZE);
	writable = is_writable(pte);

	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. if fail to insert page, do error handling. */
		printf("pml4_set_page fail:%s\n,", thread_current()->name);
		palloc_free_page (newpage);
		current->exitcode = -1;
		return false;
	}
	return true;
}
#endif

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
static void
__do_fork (void *aux) {
	struct intr_frame if_;
	struct fork_args *args = (struct fork_args *) aux;
	struct thread *parent = args->parent;
	struct thread *current = thread_current ();
	struct intr_frame *parent_if = (struct intr_frame *) args->additional;
	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame));

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	process_activate (current);
#ifdef VM
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
#else
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent))
		goto error;
#endif

	/* Your code goes here.
	 * Hint) To duplicate the file object, use `file_duplicate`
	 *       in include/filesys/file.h. Note that parent should not return
	 *       from the fork() until this function successfully duplicates
	 *       the resources of parent.*/
	process_init (parent);
	fork_file(current, parent);

	sema_up (&args->return_sema);

	/* Finally, switch to the newly created process. */
	if (succ) if_.R.rax = 0;
	do_iret (&if_);
error:
	sema_up (&args->return_sema);
	current->exitcode = -1;
	thread_exit ();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
/*
	modified
	f_name changed to input, like "grep foo bar"
	then, grep is file name and foo, bar is argv[1], argv[2]
*/
int
process_exec (void *input) {
	char *argv[32]; //proper limit of argument number
	int argc=0;
	char *token, *save_ptr;
	for (token = strtok_r (input, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr)){
		argv[argc]=token;
		argc++;
	}
	argv[argc] = (char*) 0;
	char *file_name = argv[0];
	bool success;

	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	//pass rdi and rsi to set stack
	_if.R.rsi =(uint64_t) &argv[0];
	_if.R.rdi = argc;

	lock_acquire(&filesys_lock);
	struct file* file = filesys_open ((const char*) file_name);
	lock_release(&filesys_lock);
	if (file == NULL){
		printf ("load: %s: open failed\n", file_name);
		thread_current() ->exitcode = -1;
		thread_exit();
		return -1;
	}

	/* We first kill the current context */
	process_cleanup ();
	supplemental_page_table_init (&thread_current () -> spt);
	/* And then load the binary */
	success = load (file_name, &_if);

	/* If load failed, quit. */
	palloc_free_page (input);
	if (!success)
		return -1;

	/* Start switched process. */
	do_iret (&_if);
	NOT_REACHED ();
}


/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid) {
	/* Hint) The pintos exit if process_wait (initd), we recommend you
	 *       to add infinite loop here before
	 *       implementing the process_wait. */
	struct thread *curr = thread_current ();
	int exitcode;
	struct child_info *cinfo;

	// Get child_info with child_tid
	lock_acquire (&children_info_lock);
	cinfo = get_child_info (child_tid);
	lock_release (&children_info_lock);
	if (cinfo == NULL || cinfo->parent_tid != curr->tid)
		return -1;

	// child_info sema down for wait child killed.
	sema_down (&cinfo->sema);
	// Resumed after child kill successfully
	// or pass directly to here for already killed child.

	// Get exitcode.
	exitcode = cinfo->exitcode;

	list_remove (&cinfo->elem);
	free (cinfo);

	return exitcode;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *curr = thread_current ();
	struct thread *parent = curr->parent;
	if (curr->file_itself != NULL){
		file_close(curr->file_itself);
	}
	close_all(&curr->open_file);
	if (curr->pml4 != NULL){
		// Print termination message when user process terminates
		process_cleanup ();
		printf ("%s: exit(%d)\n", curr->name, curr->exitcode);
	}
	// Check waiting process
	if (parent != NULL)
	{
		lock_acquire (&children_info_lock);
		struct child_info *cinfo = get_child_info(curr->tid);
		lock_release (&children_info_lock);

		if (cinfo != NULL && parent->tid == cinfo->parent_tid)
		{
			lock_acquire (&children_info_lock);
			// Update exit status for this tid
			cinfo->exitcode = curr->exitcode;
			// sema up for unblock or enable wait syscall
			sema_up (&cinfo->sema);
			lock_release (&children_info_lock);
		}
	}

}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	lock_acquire(&filesys_lock);
	file = filesys_open (file_name);
	lock_release (&filesys_lock);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
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
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	success = true;

done:
	/* We arrive here whether the load is successful or not. */
	if (file != NULL){
		t->file_itself = file;
		file_deny_write(file);
	}
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
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

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

#define WORD_ALIGN(addr) ((uint64_t)addr - ((uint64_t)addr/8)*8)
/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
//diffrent with document, argv[0] stored at top of stack
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO); //void* VM page start position
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success){

			char** argv = (char**) if_->R.rsi; //&argv
			uint64_t argc = if_->R.rdi; //argc
			uint64_t stack_pos = USER_STACK;
			uint64_t args_pos[32];
			for (int i=0;i<(int) argc;i++){
				size_t tmplen = strlen(argv[i]);
				stack_pos = stack_pos - tmplen -1;
				strlcpy((char*) stack_pos, argv[i], 128); //128 is max length of argument
				args_pos[i] = stack_pos;
			}
			stack_pos -= WORD_ALIGN(stack_pos);
			// Can cause problem: skipped to insert padding
			//stack_pos = (uint8_t[]) 0
			for (int i = argc;i>=0;i--){
				stack_pos-=8;
				if (i == (int) argc) *(char*)(stack_pos) = 0;
				else{
					memcpy((void *) stack_pos, &(args_pos[i]),8);
				}
				
			}
			stack_pos-=8;
			// Can cause problem: can't handle void (*) ()
			*((uint64_t*) stack_pos)= 0;
			if_->rsp = stack_pos;
			if_->R.rsi = stack_pos+8;
			if_->R.rdi=argc; 
		}
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */


static bool
lazy_load_segment (struct page *page, void *aux) {
	/* Load the segment from the file */
	/* This called when the first page fault occurs on address VA. */
	/* VA is available when calling this function. */
	struct load_info* li = (struct load_info *) aux;
	if (page == NULL) return false;
	ASSERT(li ->page_read_bytes <=PGSIZE);
	ASSERT(li -> page_zero_bytes <= PGSIZE);
	/* Load this page. */
	if (li -> page_read_bytes > 0) {
		file_seek (li -> file, li -> ofs);
		if (file_read (li -> file, page -> va, li -> page_read_bytes) != (off_t) li -> page_read_bytes) {
			vm_dealloc_page (page);
			free (li);
			return false;
		}
	}
	memset (page -> va + li -> page_read_bytes, 0, li -> page_zero_bytes);
	file_close (li -> file);
	free (li);
	return true;
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	off_t read_ofs = ofs;
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Set up aux to pass information to the lazy_load_segment. */
		struct load_info *aux = malloc (sizeof (struct load_info));
		aux -> file = file_reopen(file);
		aux -> ofs = read_ofs;
		aux -> page_read_bytes = page_read_bytes;
		aux -> page_zero_bytes = page_zero_bytes;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, (void*) aux)){
			free (aux);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
		read_ofs += PGSIZE;
	}
	return true;
}

#define WORD_ALIGN(addr) ((uint64_t)addr - ((uint64_t)addr/8)*8)
/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* Map the stack on stack_bottom and claim the page immediately.
	 * If success, set the rsp accordingly.
	 * You should mark the page is stack. */
	if (!vm_alloc_page (VM_ANON | VM_STACK, stack_bottom ,true)) return false;;
	if (!vm_claim_page(stack_bottom)) return false;
	memset(stack_bottom, 0, PGSIZE);

	char** argv = (char**) if_->R.rsi; //&argv
	uint64_t argc = if_->R.rdi; //argc
	uint64_t stack_pos = USER_STACK;
	uint64_t args_pos[32];
	for (int i=0;i<(int) argc;i++){
		size_t tmplen = strlen(argv[i]);
		stack_pos = stack_pos - tmplen -1;
		strlcpy((char*) stack_pos, argv[i], 128); //128 is max length of argument
		args_pos[i] = stack_pos;
	}
	stack_pos -= WORD_ALIGN(stack_pos);
	//stack_pos = (uint8_t[]) 0
	for (int i = argc;i>=0;i--){
		stack_pos-=8;
		if (i == (int) argc) *(char*)(stack_pos) = 0;
		else{
			memcpy((void *) stack_pos, &(args_pos[i]),8);
		}
	}
	stack_pos-=8;
	*((uint64_t*) stack_pos)= 0;
	if_->rsp = stack_pos;
	if_->R.rsi = stack_pos+8;
	if_->R.rdi=argc;

	return true;
}
#endif /* VM */
