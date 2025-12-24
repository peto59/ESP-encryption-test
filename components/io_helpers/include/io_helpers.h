#ifndef IO_HELPERS_H

#define IO_HELPERS_H

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

ssize_t robust_read(int fd, char *buf, int size);
ssize_t full_read(int fd, char *buf, int size);
ssize_t robust_write(void *, const char *, size_t);

#endif
