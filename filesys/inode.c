#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/fat.h"
#include "threads/malloc.h"
#include "filesys/directory.h"
/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	disk_sector_t start;                /* First data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t type;
	uint64_t link[4];
	char name[4][16];
	uint32_t idx;
	uint32_t unused[99];               /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP (size, DISK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	disk_sector_t sector;               /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	bool type;							/* 0: file, 1: dir */
	struct inode_disk data;             /* Inode content. */
};

void extend_inode_if_needed (struct inode *, off_t, off_t);

/* Returns the disk sector that contains byte offset POS within
 * INODE.
 * Returns -1 if INODE does not contain data for a byte at offset
 * POS. */
static disk_sector_t
byte_to_sector (const struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);
	if (pos < inode->data.length) {
		disk_sector_t sector = inode->data.start;
		while (pos >= DISK_SECTOR_SIZE) {
			sector = next_sector (sector);
			pos -= DISK_SECTOR_SIZE;
		}
		return sector;
	}
	else
		return -1;
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
bool
inode_create (disk_sector_t sector, off_t length) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
		disk_inode->idx = 0;
		if (fat_allocate (sectors, &disk_inode->start)) {
			disk_write (filesys_disk, sector, disk_inode);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;
				disk_sector_t target_sector = disk_inode->start;

				for (i = 0; i < sectors; i++) {
					disk_write (filesys_disk, target_sector, zeros);
					target_sector = next_sector (target_sector);
				}
			}
			success = true; 
		} 
		free (disk_inode);
	}
	return success;
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	disk_read (filesys_disk, inode->sector, &inode->data);
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
			fat_remove_chain (inode->sector, 0);
			fat_remove_chain (inode->data.start, 0);
		}

		free (inode); 
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
	uint8_t *buffer = buffer_;
	off_t bytes_read = 0;
	uint8_t *bounce = NULL;

	while (size > 0) {
		/* Disk sector to read, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually copy out of this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Read full sector directly into caller's buffer. */
			disk_read (filesys_disk, sector_idx, buffer + bytes_read); 
		} else {
			/* Read sector into bounce buffer, then partially copy
			 * into caller's buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}
			disk_read (filesys_disk, sector_idx, bounce);
			memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_read += chunk_size;
	}
	free (bounce);

	return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
 * Returns the number of bytes actually written, which may be
 * less than SIZE if end of file is reached or an error occurs.
 * (Normally a write at end of file would extend the inode, but
 * growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
		off_t offset) {
	const uint8_t *buffer = buffer_;
	off_t bytes_written = 0;
	uint8_t *bounce = NULL;

	if (inode->deny_write_cnt)
		return 0;

	while (size > 0) {
		extend_inode_if_needed (inode, offset, size);

		/* Sector to write, starting byte offset within sector. */
		disk_sector_t sector_idx = byte_to_sector (inode, offset);
		int sector_ofs = offset % DISK_SECTOR_SIZE;

		/* Bytes left in inode, bytes left in sector, lesser of the two. */
		off_t inode_left = inode_length (inode) - offset;
		int sector_left = DISK_SECTOR_SIZE - sector_ofs;
		int min_left = inode_left < sector_left ? inode_left : sector_left;

		/* Number of bytes to actually write into this sector. */
		int chunk_size = size < min_left ? size : min_left;
		if (chunk_size <= 0)
			break;

		if (sector_ofs == 0 && chunk_size == DISK_SECTOR_SIZE) {
			/* Write full sector directly to disk. */
			disk_write (filesys_disk, sector_idx, buffer + bytes_written); 
		} else {
			/* We need a bounce buffer. */
			if (bounce == NULL) {
				bounce = malloc (DISK_SECTOR_SIZE);
				if (bounce == NULL)
					break;
			}

			/* If the sector contains data before or after the chunk
			   we're writing, then we need to read in the sector
			   first.  Otherwise we start with a sector of all zeros. */
			if (sector_ofs > 0 || chunk_size < sector_left) 
				disk_read (filesys_disk, sector_idx, bounce);
			else
				memset (bounce, 0, DISK_SECTOR_SIZE);
			memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
			disk_write (filesys_disk, sector_idx, bounce); 
		}

		/* Advance. */
		size -= chunk_size;
		offset += chunk_size;
		bytes_written += chunk_size;
	}
	free (bounce);

	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
	void
inode_deny_write (struct inode *inode) 
{
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	return inode->data.length;
}

/* Extend inode if requested block is over EOF. */
void
extend_inode_if_needed (struct inode *inode, off_t pos, off_t size) {
	if (pos + size <= inode->data.length) return;

	// Add more sector only if required
	int required_sectors = bytes_to_sectors (pos + size);
	int current_sectors = bytes_to_sectors (inode->data.length);
	int new_sector_cnt = required_sectors - current_sectors;

	if (new_sector_cnt > 0) {
		disk_sector_t new_sector = -1;
		if (fat_allocate (new_sector_cnt, &new_sector)) {
			// New sector linking
			if (inode->data.start == 0)
				inode->data.start = new_sector;
			else {
				// Update FAT connection
				disk_sector_t last_sector = byte_to_sector (inode, inode->data.length - 1);
				cluster_t last_clst = sector_to_cluster (last_sector);
				ASSERT (fat_get (last_clst) == EOChain);
				fat_put (last_clst, sector_to_cluster (new_sector));
			}
		}
		else
			PANIC("Extend failed!");
	}

	// Update inode metadata
	inode->data.length = pos + size;
	// TODO: Should this exist only for ROOT_DIR which is zero initialized?
	/*if (inode->data.magic != INODE_MAGIC)
		inode->data.magic = INODE_MAGIC; */

	disk_write (filesys_disk, inode->sector, &inode->data);
}

void
inode_set_dir(disk_sector_t inum){
	struct inode* inode = inode_open(inum);
	disk_read (filesys_disk, inode->sector, &inode->data);
	inode->data.type = DIR_INODE;
	disk_write(filesys_disk, inode->sector, &inode->data);
	inode_close(inode);
}

void
inode_set_file(disk_sector_t inum){
	struct inode* inode = inode_open(inum);
	disk_read (filesys_disk, inode->sector, &inode->data);
	inode->data.type = FILE_INODE;
	disk_write(filesys_disk, inode->sector, &inode->data);
	inode_close(inode);
}

void
inode_set_fake(disk_sector_t inum){
	struct inode* inode = inode_open(inum);
	disk_read (filesys_disk, inode->sector, &inode->data);
	inode->data.type = FAKE_INODE;
	disk_write(filesys_disk, inode->sector, &inode->data);
	inode_close(inode);
}

int inode_type(struct inode* inode){
	return inode->data.type;
}

void
inode_set_deref(struct inode* inode, struct dir* dir, char* name){
	disk_read (filesys_disk, inode->sector, &inode->data);
	inode->data.link[inode->data.idx] = (uint64_t) dir;
	strlcpy(inode->data.name[inode->data.idx], name, 16);
	inode->data.idx++;
	if (inode->data.idx>4)
		NOT_REACHED();
	disk_write(filesys_disk, inode->sector, &inode->data);

}

void
inode_overwrite_link(struct inode* inode, struct inode* old_inode){
	disk_read (filesys_disk, old_inode->sector, &old_inode->data);
	for (int i = 0; i<old_inode->data.idx;i++){
		dir_remove_except_inode((struct dir*) old_inode->data.link[i], old_inode->data.name[i]);
		dir_add ((struct dir*) old_inode->data.link[i], old_inode->data.name, inode_get_inumber(inode));
	}
	inode_close(old_inode);
}

void inode_reactive(struct inode* inode){
	inode->removed = false;
}