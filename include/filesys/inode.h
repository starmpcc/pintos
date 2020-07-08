#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/disk.h"
#include "filesys/directory.h"
#define DIR_INODE 1
#define FILE_INODE 0
#define FAKE_INODE 2

struct bitmap;

void inode_init (void);
bool inode_create (disk_sector_t, off_t);
struct inode *inode_open (disk_sector_t);
struct inode *inode_reopen (struct inode *);
disk_sector_t inode_get_inumber (const struct inode *);
void inode_close (struct inode *);
void inode_remove (struct inode *);
off_t inode_read_at (struct inode *, void *, off_t size, off_t offset);
off_t inode_write_at (struct inode *, const void *, off_t size, off_t offset);
void inode_deny_write (struct inode *);
void inode_allow_write (struct inode *);
off_t inode_length (const struct inode *);
void inode_set_dir (disk_sector_t);
void inode_set_file (disk_sector_t);
void inode_set_fake (disk_sector_t);
int inode_type (struct inode*);
void inode_set_deref(struct inode*, struct dir*, char*);
void inode_overwrite_link(struct inode*, struct inode*);
void inode_reactive(struct inode*);
#endif /* filesys/inode.h */
