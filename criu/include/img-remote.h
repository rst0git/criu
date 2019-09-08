#ifndef __CR_IMGREMOTE_H__
#define	__CR_IMGREMOTE_H__

#include <sys/epoll.h>
#include <limits.h>
#include <stdbool.h>

#include <stdint.h>
#include "common/list.h"
#include "images/remote-image.pb-c.h"

#define FINISH 0

extern int remote_sk;
extern int pages_fd;

int remote_connect(void);
int start_img_cache(void);

int remote_send_image(const char *name, int fd_type, int pb_type, void *buf, size_t len);
int remote_send_raw_data(const char *name, int fd_type, size_t len);

bool exists_in_cache(const char *name, int fd_type);

int remote_get_raw_image_fd(const char *name, int type);
int remote_get_entry(void **entry, int fd_type, char *name, bool eof);
int remote_get_extra_data(const char *name, int fd_type, void *buf, int len, off_t offset);

int pb_read_obj(int fd, void **pobj, int fd_type);

int remote_send_finish_msg(void);
int remote_dump_finish(void);

#endif /* __CR_IMGREMOTE_H__ */
