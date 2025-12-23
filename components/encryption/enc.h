#ifndef ENC_H

#define ENC_H

#include "types.h"
#include <arpa/inet.h>
#include <stdlib.h>

int aes_op(encryption_t *handle, const unsigned char *data, size_t data_len, unsigned char *output, size_t *output_len, char increment);
int enc(encryption_t *handle, const unsigned char *line, size_t line_len);
int enc_buf(encryption_t *handle, const unsigned char *line, size_t line_len, unsigned char *output, size_t *output_len);
int dec(encryption_t *handle, const unsigned char *line, size_t line_len, unsigned char *output, size_t *output_len);

#endif
