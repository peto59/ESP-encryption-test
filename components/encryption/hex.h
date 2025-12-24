#ifdef USE_HEX_SW

#ifndef HEX_H

#define HEX_H

#include <stddef.h>


int hex_encode(void *handle, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen);
int hex_decode(void *handle, const unsigned char *input, size_t ilen, unsigned char *output, size_t *olen);

#endif
#endif
