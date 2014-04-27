#ifndef __CR_FS_MAGIC_H__
#define __CR_FS_MAGIC_H__

#include <sys/vfs.h>

/*
 * Gather magic numbers in case if distros
 * do not provide appropriate entry in
 * linux/magic.h.
 */

#ifndef NFS_SUPER_MAGIC
# define NFS_SUPER_MAGIC	0x6969
#endif

#ifndef PIPEFS_MAGIC
# define PIPEFS_MAGIC		0x50495045
#endif

#ifndef ANON_INODE_FS_MAGIC
# define ANON_INODE_FS_MAGIC	0x09041934
#endif

#ifndef TMPFS_MAGIC
# define TMPFS_MAGIC		0x01021994
#endif

#ifndef SOCKFS_MAGIC
# define SOCKFS_MAGIC		0x534f434b
#endif

#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC	0x1cd1
#endif

#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC	0x9123683E
#endif

#endif /* __CR_FS_MAGIC_H__ */
