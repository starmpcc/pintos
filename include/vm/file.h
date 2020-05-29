#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_page {
	struct file* file;
	// real written size except zero bytes
	off_t size;
	off_t ofs;
};

struct mmap_info{
	struct file* file;
	off_t offset;
	size_t read_bytes;
};

void vm_file_init (void);
bool file_map_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
