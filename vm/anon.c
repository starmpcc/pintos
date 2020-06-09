/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include <bitmap.h>
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"

#define CEILING(x, y) (((x) + (y) - 1) / (y))
#define SECTORS_PER_PAGE CEILING(PGSIZE, DISK_SECTOR_SIZE)

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

static const struct page_operations anon_stack_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON | VM_STACK,
};

static struct bitmap *swap_table;

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	/* Set up the swap_disk. */
	swap_disk = disk_get(1, 1);

	disk_sector_t num_sector = disk_size (swap_disk);
	size_t max_slot = num_sector / SECTORS_PER_PAGE;

	// Set swap table based on the max_slot
	swap_table = bitmap_create (max_slot);
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &anon_ops;
	if (type & VM_STACK) page->operations = &anon_stack_ops;
	struct anon_page *anon_page = &page->anon;
	page -> anon.owner = thread_current ();
	return true;
}

/* Swap in the page by read contents from the swap disk. */
static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_page *anon_page = &page->anon;
	if (anon_page->swap_slot_idx == NULL) return true;

	disk_sector_t sec_no;
	// Read page from disk with sector size chunk
	for (int i = 0; i < SECTORS_PER_PAGE; i++) {
		// convert swap slot index to reading sector number
		sec_no = (disk_sector_t) (anon_page->swap_slot_idx * SECTORS_PER_PAGE) + i;
		off_t ofs = i * DISK_SECTOR_SIZE;
		disk_read (swap_disk, sec_no, kva+ofs);
	}
	// Clear swap table
	bitmap_set (swap_table, anon_page->swap_slot_idx, false);

	anon_page->swap_slot_idx = NULL;

	return true;
}

/* Swap out the page by writing contents to the swap disk. */
static bool
anon_swap_out (struct page *page) {
	struct anon_page *anon_page = &page->anon;

	// Get swap slot index from swap table
	size_t swap_slot_idx = bitmap_scan_and_flip (swap_table, 0, 1, false);
	if (swap_slot_idx == BITMAP_ERROR)
		PANIC("There is no free swap slot!");

	// Copy page frame content to swap_slot
	if (page == NULL || page->frame == NULL || page->frame->kva == NULL)
		return false;

	disk_sector_t sec_no;
	// Write page to disk with sector size chunk
	for (int i = 0; i < SECTORS_PER_PAGE; i++) {
		// convert swap slot index to writing sector number
		sec_no = (disk_sector_t) (swap_slot_idx * SECTORS_PER_PAGE) + i;
		off_t ofs = i * DISK_SECTOR_SIZE;
		disk_write (swap_disk, sec_no, page->frame->kva + ofs);
	}
	anon_page->swap_slot_idx = swap_slot_idx;

	// Set "not present" to page.
	pml4_clear_page (anon_page->owner->pml4, page->va);
	page->frame = NULL;
	page->on_memory = 0;

	return true;
}

/* Destroy the anonymous page. PAGE will be freed by the caller. */
static void
anon_destroy (struct page *page) {
	free (page -> frame);
}
