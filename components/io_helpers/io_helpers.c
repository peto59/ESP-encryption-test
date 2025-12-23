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
	while(size > 0){
		ssize_t rd_cnt = robust_read(fd, buf, size);
		if(rd_cnt < 0){
			return -1;
		}
		if(rd_cnt == size){
			return 0;
		}
		buf += rd_cnt;
		size -= rd_cnt;
	}
	return 0;
}

ssize_t robust_write(void *handle, const char *c, size_t l){
	(void) handle;
	printf("output from library: %s\n", c);
	return l;
}
