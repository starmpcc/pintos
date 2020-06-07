/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "intrinsic.h"
#include <string.h>
#include "threads/vaddr.h"

static struct lock spt_kill_lock;
/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&spt_kill_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

static uint64_t page_hash (const struct hash_elem *p_, void *aux UNUSED);
static bool page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`.*/
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	struct supplemental_page_table *spt = &thread_current ()->spt;
	bool writable_aux = writable;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* Create the page, fetch the initialier according to the VM type,
		 * and then create "uninit" page struct by calling uninit_new. You
		 * should modify the field after calling the uninit_new. */

		ASSERT(type != VM_UNINIT);
		/* Insert the page into the spt. */
		struct page* page = malloc (sizeof (struct page));
		if (VM_TYPE(type) == VM_ANON){
			uninit_new (page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE(type) == VM_FILE){
			uninit_new (page, upage, init, type, aux, file_map_initializer);
		}

		page -> writable = writable_aux;
		page -> on_memory = 0;
		spt_insert_page (spt, page);
		return true;
	}
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page page;
	page.va = pg_round_down (va);
	struct hash_elem *e = hash_find (spt -> page_table, &page.hash_elem);
	if (e == NULL) return NULL;
	struct page* result = hash_entry (e, struct page, hash_elem);
	ASSERT((va < result -> va + PGSIZE) && va >= result -> va);
	return result;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	struct hash_elem *result= hash_insert (spt -> page_table, &page -> hash_elem);
	return (result == NULL) ? true : false ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	struct hash_elem* e = hash_delete (spt -> page_table, &page ->hash_elem);
	if (e != NULL) vm_dealloc_page (page);
	return;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	/* Simple Clock Algorithm with Vairable Space? */
	struct frame *candidate = NULL;
	struct thread *curr = thread_current ();

	struct list_elem *cand_elem = curr->clock_elem;
	if (cand_elem == NULL && !list_empty (&curr->frame_list))
	      cand_elem = list_front (&curr->frame_list);

	while (cand_elem != NULL) {
	      // Check frame accessed
	      candidate = list_entry (cand_elem, struct frame, elem);
	      if (!pml4_is_accessed (curr->pml4, candidate->page->va))
		    break; // Found!
	      pml4_set_accessed (curr->pml4, candidate->page->va, false);

	      if (cand_elem == list_end (&curr->frame_list))
		    // Repeat from the front
		    cand_elem = list_front (&curr->frame_list);
	      else
		    cand_elem = list_next (cand_elem);
	}

	if (cand_elem != NULL)
	      curr->clock_elem = list_next (cand_elem);
	return candidate;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	if (victim == NULL) return NULL;

	/* Swap out the victim and return the evicted frame. */
	struct page *page = victim->page;
	bool swap_done = swap_out (page);
	if (!swap_done) PANIC("Swap is full!\n");

	// Clear frame
	victim->page = NULL;
	memset (victim->kva, 0, PGSIZE);
	list_remove (&victim->elem);

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame * frame = malloc (sizeof (frame));
	// TODO(chanil): malloc returns same address which cause error
	printf("vm_get_frame called, frame ptr: %p\n", (void *)frame);
	frame -> kva = palloc_get_page (PAL_USER);
	frame -> page = NULL;
	// Add swap case handling
	if (frame->kva == NULL) {
	  free (frame);
	  frame = vm_evict_frame ();
	}
	ASSERT (frame->kva != NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	void *stack_bottom = pg_round_down (addr);
	size_t req_stack_size = USER_STACK - (uintptr_t)stack_bottom;
	if (req_stack_size > (1 << 20)) PANIC("Stack limit exceeded!\n"); // 1MB

	// Alloc page from tested region to previous claimed stack page.
	void *growing_stack_bottom = stack_bottom;
	while (growing_stack_bottom < USER_STACK &&
		vm_alloc_page (VM_ANON | VM_STACK, growing_stack_bottom, true)) {
	      growing_stack_bottom += PGSIZE;
	};
	vm_claim_page (stack_bottom); // Lazy load requested stack page only
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	return false;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr,
		bool user, bool write, bool not_present) {
	struct thread *curr = thread_current ();
	struct supplemental_page_table *spt = &curr->spt;
	/* Validate the fault */
	if (is_kernel_vaddr (addr) && user) return false;
	if (write && (addr == curr->saved_sp - 8)) {
	  /* The x86-64 PUSH instruction checks access permissions
	   * before it adjusts the stack pointer, so it may cause
	   * a page fault 8 bytes below the stack pointer. */
	  /* Or not allocated stack region access. */
	  vm_stack_growth (addr);
	  return true;
	}
	struct page* page = spt_find_page (spt, addr);
	if (page == NULL) return false;
	if (write && !not_present) return vm_handle_wp (page);
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va) {
	struct page *page = spt_find_page (&thread_current () ->spt, va);
	if (page == NULL) return false;
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *curr = thread_current ();
	struct frame *frame = vm_get_frame ();
	printf("frame pointer: %p %p\n", page, frame);
	/* Set links */
	ASSERT (frame != NULL);
	ASSERT (page != NULL);
	frame->page = page;
	page->frame = frame;

	// Add to frame_list for eviction clock algorithm
	if (curr->clock_elem != NULL)
		// Just before current clock
		list_insert (curr->clock_elem, &frame->elem);
	else
		// TODO(chanil): comment list_push_back make error removed
		list_push_back (&curr->frame_list, &frame->elem);

	/* Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page (curr -> pml4, page -> va, frame->kva, page -> writable))
		return false;
	return swap_in (page, frame->kva);
}


static uint64_t
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

static bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	struct hash* page_table = malloc(sizeof (struct hash));
	hash_init (page_table, page_hash, page_less, NULL);
	spt -> page_table = page_table;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	/*Iterate Source spt hash table*/
	struct hash_iterator i;
	hash_first (&i, src -> page_table);
	while (hash_next (&i)) {
		struct page *page = hash_entry (hash_cur (&i), struct page, hash_elem);

		/*Handle UNINIT page*/
		if (page -> operations -> type == VM_UNINIT){
			vm_initializer* init = page ->uninit.init;
			bool writable = page -> writable;
			int type = page ->uninit.type;
			if (type & VM_ANON){
				struct load_info* li = malloc (sizeof (struct load_info));
				li -> file = file_duplicate (((struct load_info *) page -> uninit .aux)->file);
				li -> page_read_bytes = ((struct load_info *) page -> uninit .aux)->page_read_bytes;
				li -> page_zero_bytes = ((struct load_info *) page -> uninit .aux)->page_zero_bytes;
				li -> ofs = ((struct load_info *) page -> uninit .aux)->ofs;
				vm_alloc_page_with_initializer (type, page -> va, writable, init, (void*) li);
			}
			else if (type & VM_FILE){
				//Do_nothing(it should not inherit mmap)
			}

		}
		
		/* Handle ANON/FILE page*/
		else if (page_get_type(page) == VM_ANON){
			if (!vm_alloc_page (page -> operations -> type, page -> va, page -> writable))
				return false;
			struct page* new_page = spt_find_page (&thread_current () -> spt, page -> va);
			if (!vm_do_claim_page (new_page))
				return false;
			memcpy (new_page -> frame -> kva, page -> frame -> kva, PGSIZE);
		}
		else if (page_get_type(page) == VM_FILE){
			//Do nothing(it should not inherit mmap)
		}
	}
	return true;
}

static void
spt_destroy (struct hash_elem *e, void *aux UNUSED){
	struct page *page = hash_entry (e, struct page, hash_elem);
	ASSERT (page != NULL);
	destroy (page);
	free (page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* Destroy all the supplemental_page_table hold by thread and
	 * writeback all the modified contents to the storage. */
	if (spt -> page_table == NULL) return;
	lock_acquire(&spt_kill_lock);
	hash_destroy (spt -> page_table, spt_destroy);
	free (spt -> page_table);
	lock_release(&spt_kill_lock);
}
