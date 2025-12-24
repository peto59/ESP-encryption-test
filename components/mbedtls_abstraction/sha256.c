#include "sha256.h"

int sha256_calc(void *handle, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen){
	(void) handle;
	if(*olen < 32){
		return -1;
	}
	*olen = 32;

	return mbedtls_sha256(input, ilen, output, 0);
}
