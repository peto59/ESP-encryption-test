#include "include/io_helpers.h"
#ifdef DEBUG
#include <string.h>
#endif

ssize_t robust_read(int fd, char *buf, int size){
	//almost busy wait
	int real_size = 0;
	ssize_t rd_cnt;
	while(real_size < size){
		rd_cnt = read(fd, buf, size - real_size);
#ifdef DEBUG
		printf("real_size %d\n", real_size);
		printf("read %d \n", rd_cnt);
		printf("err %s \n", strerror(errno));
		printf("errno %d \n", errno);
#endif
		if(rd_cnt < 0){
			if(errno == EAGAIN){
				sleep(1);
				continue;
			}
			return real_size;
		}

		real_size += rd_cnt;

		for(ssize_t i = 0; i < rd_cnt; i++){
			if(buf[i] == '\n'){
				return real_size;
			}
		}

		buf += rd_cnt;
	}

	return real_size;
}

ssize_t full_read(int fd, char *buf, int size){
	//almost busy wait
	int real_size = 0;
	ssize_t rd_cnt;
	while(real_size < size){
		rd_cnt = read(fd, buf, size - real_size);
#ifdef DEBUG
		printf("real_size %d\n", real_size);
		printf("read %d \n", rd_cnt);
		printf("err %s \n", strerror(errno));
		printf("errno %d \n", errno);
#endif
		if(rd_cnt < 0){
			if(errno == EAGAIN){
				sleep(1);
				continue;
			}
			return real_size;
		}

		real_size += rd_cnt;
		buf += rd_cnt;
	}
    return size;
}

ssize_t robust_write(void *handle, const char *c, size_t l){
	(void) handle;
    char b[l + 1];
    memcpy(b, c, l);
    b[l] = '\0';
	printf("output from library: %s\n", b);
	return l;
}
