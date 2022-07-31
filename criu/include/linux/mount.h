#ifndef _CRIU_LINUX_MOUNT_H
#define _CRIU_LINUX_MOUNT_H

#include "common/config.h"
#include "compel/plugins/std/syscall-codes.h"

#ifndef FSCONFIG_CMD_CREATE
/* The type of fsconfig call made.   */
enum fsconfig_command {
	FSCONFIG_SET_FLAG = 0, /* Set parameter, supplying no value */
#define FSCONFIG_SET_FLAG FSCONFIG_SET_FLAG
	FSCONFIG_SET_STRING = 1, /* Set parameter, supplying a string value */
#define FSCONFIG_SET_STRING FSCONFIG_SET_STRING
	FSCONFIG_SET_BINARY = 2, /* Set parameter, supplying a binary blob value */
#define FSCONFIG_SET_BINARY FSCONFIG_SET_BINARY
	FSCONFIG_SET_PATH = 3, /* Set parameter, supplying an object by path */
#define FSCONFIG_SET_PATH FSCONFIG_SET_PATH
	FSCONFIG_SET_PATH_EMPTY = 4, /* Set parameter, supplying an object by (empty) path */
#define FSCONFIG_SET_PATH_EMPTY FSCONFIG_SET_PATH_EMPTY
	FSCONFIG_SET_FD = 5, /* Set parameter, supplying an object by fd */
#define FSCONFIG_SET_FD FSCONFIG_SET_FD
	FSCONFIG_CMD_CREATE = 6, /* Invoke superblock creation */
#define FSCONFIG_CMD_CREATE FSCONFIG_CMD_CREATE
	FSCONFIG_CMD_RECONFIGURE = 7, /* Invoke superblock reconfiguration */
#define FSCONFIG_CMD_RECONFIGURE FSCONFIG_CMD_RECONFIGURE
};
#endif

static inline int sys_fsopen(const char *fsname, unsigned int flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}
static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key, const char *value, int aux)
{
	return syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}
static inline int sys_fsmount(int fd, unsigned int flags, unsigned int attr_flags)
{
	return syscall(__NR_fsmount, fd, flags, attr_flags);
}

#endif
